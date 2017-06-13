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

from pki.lib.tree_entries import (
    MSCEntry,
    RevocationEntry,
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


class LogServer(EEPKIElement):
    def __init__(self, addr):
        # Init network
        super().__init__(addr)
        # Init log
        entries = self.init_db()
        self.log = Log(entries)
        self.lock = threading.Lock()

    def init_db(self):
        return []

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
                self.handle_add_scp(msg, meta)
            elif isinstance(msg.entry, MSCEntry):
                self.handle_add_msc(msg, meta)
            elif isinstance(msg.entry, RevocationEntry):
                self.handle_add_rev(msg, meta)
            else:
                self.handle_error(meta, "No handler for entry")
        else:
            self.handle_error(meta, "No handler for request")

    def has_lock(self, meta):
        # When log is under an update
        if not self.lock.acquire(blocking=False):
            self.handle_error(meta, "Service temporarily unavailable")
            return False
        return True

    def handle_error(self, meta, desc):
        msg = ErrorMsg.from_values(desc)
        self.send_meta(meta, msg.pack())

    def handle_root_request(self, msg, meta): 
        if not self.has_lock(meta):
            return

    def handle_proof_request(self, msg, meta): 
        if not self.has_lock(meta):
            return

    def handle_update_request(self, msg, meta): 
        if not self.has_lock(meta):
            return

    def handle_add_scp(self, msg, meta): 
        if not self.has_lock(meta):
            return

    def handle_add_msc(self, msg, meta): 
        if not self.has_lock(meta):
            return

    def handle_add_rev(self, msg, meta): 
        if not self.has_lock(meta):
            return
    
    def worker(self):
        raise NotImplementedError


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("%s <ISD-AS> <IP>" % sys.argv[0])
        # PYTHONPATH=..:../scion python3 log/server.py 1-17 127.1.1.1
        sys.exit()
    addr = SCIONAddr.from_values(ISD_AS(sys.argv[1]), haddr_parse(1, sys.argv[2]))
    log_serv = LogServer(addr)
    print("running log")
    log_serv.run()
