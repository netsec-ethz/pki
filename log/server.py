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
import time
import threading
from merkle import hash_function

from pki.lib.tree_entries import (
    MSCEntry,
    RevocationEntry,
    RootsEntry,
    SCPEntry,
)
from pki.log.elem import EEPKIElement
from pki.log.log import Log
from pki.log.msg import (
    AcceptMsg,
    AddMsg,
    ErrorMsg,
    ProofMsg,
    SignedRoot,
    UpdateMsg,
)

# SCION
from lib.packet.host_addr import haddr_parse
from lib.packet.scion_addr import ISD_AS, SCIONAddr
from lib.thread import thread_safety_net
from lib.util import sleep_interval


def try_lock(handler):
    def wrapper(inst, meta, obj):
        # When log is under an update
        if not inst.lock.acquire(blocking=False):
            inst.handle_error(meta, "Service temporarily unavailable")
            return
        handler(inst, meta, obj)
        inst.lock.release()
    return wrapper


class LogServer(EEPKIElement):
    UPDATE_INTERVAL = 10  # FIXME(PSz): so low for testing
    def __init__(self, addr):
        # Init log
        self.priv_key = None
        entries = self.init_db()
        self.log = Log(entries)
        self.lock = threading.Lock()
        self.entries_to_add = []
        self.signed_root = None
        self.update_root()
        # Init network
        super().__init__(addr)

    def init_db(self):
        return []

    def update_root(self):
        root, entries_no = self.log.get_root_entries()
        self.signed_root = SignedRoot.from_values(root, entries_no, self.priv_key)

    def handle_msg_meta(self, msg, meta):
        """
        Main routine to handle incoming SCION messages.
        """
        if isinstance(msg, SignedRoot):
            self.handle_root_request(msg, meta)
        elif isinstance(msg, ProofMsg):
            self.handle_proof_request(msg, meta)
        elif isinstance(msg, UpdateMsg):
            self.handle_update_request(msg, meta)
        elif isinstance(msg, AddMsg):
            if isinstance(msg.entry, SCPEntry):
                self.handle_add(msg.entry, msg.entry.scp, meta)
            elif isinstance(msg.entry, MSCEntry):
                self.handle_add(msg.entry, msg.entry.msc, meta)
            elif isinstance(msg.entry, RevocationEntry):
                self.handle_add(msg.entry, msg.entry.rev, meta)
            else:
                self.handle_error(meta, "No handler for entry")
        else:
            self.handle_error(meta, "No handler for request")

    def handle_error(self, meta, desc):
        msg = ErrorMsg.from_values(desc)
        self.send_meta(meta, msg.pack())

    @try_lock
    def handle_root_request(self, msg, meta):
        self.send_meta(meta, self.signed_root.pack())

    @try_lock
    def handle_proof_request(self, msg, meta):
        proof = self.log.get_proof(msg.domain_name, msg.msc_label)
        msg.eepki_proof = proof
        self.send_meta(meta, msg.pack())

    @try_lock
    def handle_update_request(self, msg, meta):
        msg.entries = self.log.entries[msg.entry_from:msg.entry_to]
        self.send_meta(meta, msg.pack())

    @try_lock
    def handle_add(self, entry, obj, meta):
        # TODO(PSz): entry has to be writted to DB as it has metadata
        if not self.verify(obj):
            msg = ErrorMsg.from_values("Verification failed")
            self.send_meta(meta, msg.pack())
            return
        self.entries_to_add.append(obj)
        hash_ = hash_function(obj.pack()).digest()
        msg = AcceptMsg.from_values(hash_, self.priv_key)
        self.send_meta(meta, msg.pack())

    def verify(self, obj):
        return True

    def worker(self):
        start = time.time()
        while self.run_flag.is_set():
            sleep_interval(start, self.UPDATE_INTERVAL, "LogServer.worker sleep",
                           self._quiet_startup())
            start = time.time()
            self.update()

    def update(self):
        with self.lock:
            logging.debug("Starting log update")
            for entry in self.entries_to_add:
                self.log.add(entry)
            self.log.build()
            self.update_root()
            self.entries_to_add = []
            logging.debug("Log updated")

    def run(self):
        threading.Thread(
            target=thread_safety_net, args=(self.worker,),
            name="LogServer.worker", daemon=True).start()
        super().run()

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("%s <ISD-AS> <IP>" % sys.argv[0])
        # PYTHONPATH=..:../scion python3 log/server.py 1-17 127.1.1.1
        sys.exit()
    addr = SCIONAddr.from_values(ISD_AS(sys.argv[1]), haddr_parse(1, sys.argv[2]))
    log_serv = LogServer(addr)
    print("running log")
    log_serv.run()
