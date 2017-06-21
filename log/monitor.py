# Copyright 2017 ETH Zurich
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import logging
import sys
import threading
import time

from pki.lib.defines import EEPKI_PORT
from pki.log.elem import EEPKIElement
from pki.log.log import Log
from pki.log.msg import (
    ErrorMsg,
    RootConfirm,
    SignedRoot,
    UpdateMsg,
)
from pki.lib.tree_entries import (
    MSCEntry,
    RevocationEntry,
    RootsEntry,
    SCPEntry,
    )

# SCION
from lib.crypto.trc import TRC
from lib.packet.host_addr import haddr_parse
from lib.packet.scion_addr import ISD_AS, SCIONAddr
from lib.thread import thread_safety_net
from lib.util import sleep_interval


class LogMonitor(EEPKIElement):
    MONITOR_INTERVAL = 2
    def __init__(self, addr):
        logging.basicConfig(level=logging.DEBUG, format="%(asctime)-15s %(message)s")
        self.my_id = "monitor1"
        self.pub_key = b'5w\x9c\xb6\xa1\xef\x8a\x95\xfd\x8d\xd6\x9bd\xbd\x1a\x9aN\r\xcaj6i=\xe2\xb1\xbe\xad\xe9\xad\x94\xc1\x00'
        self.priv_key = b"H\x05\xa7\x1b\xe7t\xdfF\xd4\xe6\xb67\x8a'#\x13\x1cc\xa2\xf4\xccI\xffU\xe1-W\xc8>.\x08\x94"
        # Init log data structures
        self.log2addr = {}
        self.logs = {}
        self.log2lock = {}
        self.log2key = {}
        self.signed_roots = {}
        self.confirmed_roots = {}
        # These are for communication only. Should be expiring.
        self.asked_roots = {}
        self.asked_updates = {}
        # Init logs
        self.init_logs()
        # Init network
        super().__init__(addr)

    def init_logs(self):
        # TODO(PSz): read from TRC
        addr = SCIONAddr.from_values(ISD_AS("1-17"), haddr_parse(1, "127.1.1.1"))
        self.log2addr = {"log1": addr}
        for log_id in self.log2addr:
            self.logs[log_id] = Log()
            self.log2lock[log_id] = threading.Lock()
            self.log2key[log_id] = b'\xfd\xd99\xb3\x9e-\xa4%1\x80H\x9c\xd72?\xb1tCW;\xa1\x1b_o\xf8\xe8\xcf\xca\xdb\x0b>\x12'
            self.signed_roots[log_id] = {}
            self.confirmed_roots[log_id] = {}
            self.asked_roots[log_id] = []
            self.asked_updates[log_id] = []

    def handle_msg_meta(self, msg, meta):
        """
        Main routine to handle incoming SCION messages.
        """
        if isinstance(msg, SignedRoot):
            self.handle_root(msg, meta)
        elif isinstance(msg, UpdateMsg):
            self.handle_update(msg, meta)
        elif isinstance(msg, RootConfirm):
            self.handle_confirm_request(msg, meta)
        elif isinstance(msg, ErrorMsg):
            self.handle_error(msg, meta)
        else:
            self.send_error(meta, "No handler for request: %s" % msg)

    def handle_error(self, msg, meta):
        logging.error("Received: %s" % msg)

    def send_error(self, desc, meta):
        msg = ErrorMsg.from_values(desc)
        self.send_meta(msg, meta)

    def handle_root(self, msg, meta):
        log_id = msg.log_id
        if not msg.validate(self.log2key[log_id]):
            logging.error("Cannot validate: %s" % msg)
            return
        idx = msg.root_idx
        if idx in self.signed_roots[log_id] and msg != self.signed_roots[log_id][idx]:
            logging.critical("Inconsistent roots: %s\n%s" % msg, self.signed_roots[log_id][idx])
            return
        self.signed_roots[log_id][idx] = msg
        logging.debug("Received root: %s" % msg)
        self.sync_log(log_id, meta)

    def sync_log(self, log_id, meta):
        # First collect intermediate roots (if any is missing)
        max_ = max(self.signed_roots[log_id].keys())
        missing = range(0, max_ + 1) - self.signed_roots[log_id].keys()
        logging.debug("Missing: %s, max %s" % (missing, max_))
        for idx in missing:
            if idx not in self.asked_roots[log_id]:
                self.ask_root(meta, idx)
                self.asked_roots[log_id].append(idx)
        if missing: # Wait for roots before syncing content
            return
        # Ask for update of the first nonsynced root
        root = self.first_nonsync_root(log_id)
        if not root:
            logging.debug("Log: %s is up to date" % log_id)
            return
        if root.root_idx not in self.asked_updates[log_id]:
            self.ask_update(meta, root)
            self.asked_updates[log_id].append(root.root_idx)

    def ask_root(self, meta, idx=None):
        req = SignedRoot()
        if idx is not None:
            req.root_idx = idx
        logging.debug("Asking for root: %s" % req)
        self.send_meta(req, meta)

    def first_nonsync_root(self, log_id):
        for idx in sorted(self.signed_roots[log_id].keys()):
            if idx not in self.confirmed_roots[log_id]:
                return self.signed_roots[log_id][idx]
        return None

    def ask_update(self, meta, root):
        """
        root: the first non-synchronized root
        """
        # TODO(PSz): here some state could limit sending redundant requests
        _, entries = self.logs[root.log_id].get_root_entries()
        req = UpdateMsg.from_values(entries, root.entries_no)
        logging.debug("Asking for Update: %s" % req)
        self.send_meta(req, meta)

    def handle_update(self, msg, meta):
        # TODO(PSz): to long, entry matching can be in log's add_entry()
        log_id = msg.log_id
        log = self.logs[log_id]
        # First validate the update
        _, entries = log.get_root_entries()
        if entries != msg.entry_from:
            logging.error("Invalid entry_from in update: %d!=%d" % (entries, msg.entry_from))
            return  # TODO(PSz): what to do here?
        root = self.first_nonsync_root(log_id)
        if not root:
            logging.error("Update for synchronized log")
            return
        if root.entries_no != msg.entry_to:
            logging.error("Invalid entry_to in update: %d!=%d" % (root.entries_no, msg.entry_to))
            return  # TODO(PSz): what to do here?
        if len(msg.entries) != msg.entry_to - msg.entry_from:
            logging.error("Number of entries incorrect")
            return
        # Check received entries
        if msg.entries and not isinstance(msg.entries[-1], RootsEntry):
            logging.error("The last entry is not RootsEntry")
            return
        # Can add entries now
        for entry in msg.entries:
            try:
                # TODO(PSz): pre-validate entries here, similar as log servers do
                log.add_entry(entry)
            except EEPKIError as e:
                logging.error(e)
                return
        # Build log
        log.build(add_re=False)
        log.get_root_entries()
        new_root, new_entries = log.get_root_entries()
        if new_root != root.root:
            logging.error("Inconsistent roots after log update: %s!=%s" % (new_root, msg.root))
            return  # TODO(PSz): what to do here? Undo changes and try again?
        # The log is updated
        rc = RootConfirm.from_values(root, self.my_id, self.priv_key)
        self.confirmed_roots[log_id][root.root_idx] = rc
        logging.debug("log: %s updated" % log_id)

    def handle_confirm_request(self, msg, meta):
        pass

    def worker(self):
        start = time.time()
        while self.run_flag.is_set():
            sleep_interval(start, self.MONITOR_INTERVAL, "LogMonitor.worker sleep",
                           self._quiet_startup())
            start = time.time()
            self.ask_for_roots()

    def ask_for_roots(self):
        for addr in self.log2addr.values():
            req = SignedRoot()
            meta = self._build_meta(addr.isd_as, addr.host, port=EEPKI_PORT, reuse=True)
            self.send_meta(req, meta)

    def run(self):
        threading.Thread(
            target=thread_safety_net, args=(self.worker,),
            name="LogMonitor.worker", daemon=True).start()
        super().run()

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("%s <ISD-AS> <IP>" % sys.argv[0])
        # PYTHONPATH=..:../scion python3 log/monitor.py 1-17 127.3.4.5
        sys.exit(-1)
    addr = SCIONAddr.from_values(ISD_AS(sys.argv[1]), haddr_parse(1, sys.argv[2]))
    log_monitor = LogMonitor(addr)
    print("running monitor")
    log_monitor.run()
