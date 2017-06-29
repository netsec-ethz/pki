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

from pki.lib.defines import CONF_DIR, CONF_FILE, EEPKI_PORT, OUTPUT_DIR
from pki.lib.msg import (
    ErrorMsg,
    RootConfirm,
    RootConfirmReq,
    SignedRoot,
    UpdateMsg,
)
from pki.lib.tree_entries import (
    MSCEntry,
    RevocationEntry,
    RootsEntry,
    SCPEntry,
)
from pki.log.elem import EEPKIElement
from pki.log.log import Log

# SCION
import lib.app.sciond as lib_sciond
from lib.packet.host_addr import haddr_parse
from lib.packet.scion_addr import ISD_AS, SCIONAddr
from lib.thread import thread_safety_net
from lib.topology import Element
from lib.util import sleep_interval
from test.integration.base_cli_srv import get_sciond_api_addr


class LogMonitor(EEPKIElement):
    MONITOR_INTERVAL = 2
    def __init__(self, conf_file, priv_key_file, my_id):
        # Init configuration and network
        super().__init__(conf_file, priv_key_file, my_id)
        # Init log data structures
        self.logs = {}
        self.log2lock = {}
        self.signed_roots = {}
        self.confirmed_roots = {}
        # These are for communication only. Should be expiring.
        self.asked_roots = {}
        self.asked_updates = {}
        # Request for non-synchronized roots. TODO(PSz): should be expiring
        self.waiting = []
        # Init logs
        self.init_logs()

    def init_logs(self):
        for log_id in self.conf.logs:
            self.logs[log_id] = Log()
            self.log2lock[log_id] = threading.Lock()
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
        elif isinstance(msg, RootConfirmReq):
            self.handle_confirm_request(msg, meta)
        elif isinstance(msg, ErrorMsg):
            self.handle_error(msg, meta)
        else:
            self.send_error("No handler for request: %s" % msg, meta)

    def handle_error(self, msg, meta):
        logging.error("Received: %s" % msg)

    def send_error(self, desc, meta):
        msg = ErrorMsg.from_values(desc)
        self.send_meta(msg, meta)

    def handle_root(self, msg, meta):
        log_id = msg.log_id
        if not msg.validate(self.conf.get_pubkey(log_id)):
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
        logging.debug("asked_updates: %s" % self.asked_updates)
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
        with self.log2lock[log_id]:
            log.build(add_re=False)
            new_root, new_entries = log.get_root_entries()
            if new_root != root.root:
                logging.error("Inconsistent roots after log update: %s!=%s" % (new_root, msg.root))
                return  # TODO(PSz): what to do here? Undo changes and try again?
            # The log is updated
            rc = RootConfirm.from_values(root, self.conf.my_id, self.conf.privkey)
            self.confirmed_roots[log_id][root.root_idx] = rc
        logging.debug("log: %s updated with root_idx=%d" % (log_id, root.root_idx))
        self.handle_waiting()
        # Check for another update:
        self.sync_log(log_id, meta)

    def handle_waiting(self):
        for (req, meta) in self.waiting[:]:
            if req.root_idx in self.confirmed_roots[req.log_id]:
                rc = self.confirmed_roots[req.log_id][req.root_idx]
                self.send_meta(rc, meta)
                self.waiting.remove((req, meta))
                logging.debug("handled waiting req")

    def handle_confirm_request(self, req, meta):
        logging.debug("Asked to confirm: (%s,%d)" % (req.log_id, req.root_idx))
        if req.log_id not in self.confirmed_roots:
            self.send_error("Log %s unknown" % req.log_id, meta)
            return
        if req.root_idx not in self.confirmed_roots[req.log_id]:
            logging.debug("Added to waiting %s" % req)
            self.waiting.append((req, meta))
            return
        rc = self.confirmed_roots[req.log_id][req.root_idx]
        self.send_meta(rc, meta)

    def worker(self):
        start = time.time()
        while self.run_flag.is_set():
            sleep_interval(start, self.MONITOR_INTERVAL, "LogMonitor.worker sleep",
                           self._quiet_startup())
            start = time.time()
            self.ask_for_roots()

    def ask_for_roots(self):
        for tmp in self.conf.logs.values():
            req = SignedRoot()
            path = self.get_path(tmp.addr.isd_as)
            if not path and self.addr.isd_as != tmp.addr.isd_as:
                logging.warning("Cannot get a path to %s" % tmp.addr.isd_as)
                continue
            meta = self._build_meta(tmp.addr.isd_as, tmp.addr.host, path=path,
                                    port=EEPKI_PORT, reuse=True)
            self.send_meta(req, meta)

    def run(self):
        threading.Thread(
            target=thread_safety_net, args=(self.worker,),
            name="LogMonitor.worker", daemon=True).start()
        super().run()

    def get_path(self, dst_isd_as):
        lib_sciond.init(get_sciond_api_addr(self.addr))
        replies = lib_sciond.get_paths(dst_isd_as)
        if not replies:
            return None
        # TODO(PSz): Very hacky to avoid changing scion_elem and/or giving topo files for
        # every element.
        path = replies[0].path().fwd_path()
        ifid = path.get_fwd_if()
        if ifid not in self.ifid2br:
            br = Element()
            br.addr = replies[0].first_hop().ipv4()
            br.port = replies[0].first_hop().p.port
            self.ifid2br[ifid] = br
        return path


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("%s monitor_id" % sys.argv[0])
        # PYTHONPATH=..:../scion python3 log/monitor.py 1-17 127.3.4.5
        sys.exit(-1)
    id_ = sys.argv[1]
    conf_file = OUTPUT_DIR + CONF_DIR + CONF_FILE
    priv_key_file = OUTPUT_DIR + CONF_DIR + id_ + ".priv"
    log_monitor = LogMonitor(conf_file, priv_key_file, id_)
    print("running monitor")
    log_monitor.run()
