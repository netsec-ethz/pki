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
    CertificateEntry,
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

PRIV_KEY = b']\xc1\xdc\x07o\x0c\xa2(\x95JA\xdc\xcd\x9ez\xc2!\xd2\x82\xe0cK?\xf2X\xb1H\xe7\xcf\xf7\xad\xf4'
PUB_KEY = b'\xfd\xd99\xb3\x9e-\xa4%1\x80H\x9c\xd72?\xb1tCW;\xa1\x1b_o\xf8\xe8\xcf\xca\xdb\x0b>\x12'


def try_lock(handler):
    def wrapper(inst, obj, meta):
        # TODO(PSz): for now just wait when log is under an update (can be optimized
        # with computing log in the memory and replacing the instance)
        with inst.lock:
            handler(inst, obj, meta)
        # if not inst.lock.acquire(blocking=False):
        #     inst.handle_error("Service temporarily unavailable", meta)
        #     return
        # handler(inst, obj, meta)
        # inst.lock.release()
    return wrapper


class LogServer(EEPKIElement):
    UPDATE_INTERVAL = 10  # FIXME(PSz): so low for testing
    def __init__(self, addr):
        logging.basicConfig(level=logging.DEBUG, format="%(asctime)-15s %(message)s")
        # Init log
        self.priv_key = PRIV_KEY
        self.pub_key = PUB_KEY
        entries = self.init_db()
        self.log = Log(entries)
        self.lock = threading.Lock()
        self.mscs_to_add = []
        self.scps_to_add = []
        self.revs_to_add = []
        self.signed_roots = []
        self.update_root()
        # Init network
        super().__init__(addr)

    def init_db(self):
        return []

    def update_root(self):
        root, entries_no = self.log.get_root_entries()
        root_idx = len(self.signed_roots)
        self.signed_roots.append(SignedRoot.from_values(root, root_idx, entries_no, self.priv_key))

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
            # FIXME(PSz): adding *Entry instances may be cleaner
            if isinstance(msg.entry, SCPEntry):
                self.handle_add_scp(msg.entry.scp, meta)
            elif isinstance(msg.entry, MSCEntry):
                self.handle_add_msc(msg.entry.msc, meta)
            elif isinstance(msg.entry, RevocationEntry):
                self.handle_add_rev(msg.entry.rev, meta)
            else:
                self.handle_error(meta, "No handler for entry")
        else:
            self.handle_error(meta, "No handler for request")

    def handle_error(self, desc, meta):
        msg = ErrorMsg.from_values(desc)
        self.send_meta(msg, meta)

    @try_lock
    def handle_root_request(self, msg, meta):
        idx = msg.root_idx
        if idx is None:
            idx = -1
        try:
            self.send_meta(self.signed_roots[idx], meta)
        except IndexError:
            self.handle_error("No root for index %d" % idx, meta)

    @try_lock
    def handle_proof_request(self, msg, meta):
        proof = self.log.get_proof(msg.domain_name, msg.msc_label)
        msg.eepki_proof = proof
        self.send_meta(msg, meta)
        if msg.append_root:
            self.handle_root_request(msg, meta)

    @try_lock
    def handle_update_request(self, msg, meta):
        msg.entries = self.log.cons_tree.entries[msg.entry_from:msg.entry_to]
        self.send_meta(msg, meta)

    @try_lock
    def handle_add_scp(self, scp, meta):
        err = self.validate_scp(scp)
        if err:
            msg = ErrorMsg.from_values(err)
            self.send_meta(msg, meta)
            return
        self.scps_to_add.append(scp)
        self.accept(scp, meta)

    def validate_scp(self, scp):
        """
        Verify SCP and check if it can be added.
        """
        # Check whether this SCP is a subsequent (or the first) one
        label = scp.get_domain_name()
        latest = None
        for tmp in reversed(self.scps_to_add):
            if tmp.get_domain_name() == label:
                latest = tmp
                break
        else:
            scpe = self.log.policy_tree.get_entry(label)
            if scpe:
                latest = scpe.scp
        if not latest and scp.get_version() != 1:
            return "First SCP is missing"
        if latest:
            if latest.get_version() + 1 != scp.get_version():
                return "Latest known SCP is %d" % latest.get_version()
            pass # Validate SCP update here (i.e., latest against scp)
        # TODO(PSz): validate SCP crypto..
        return None

    @try_lock
    def handle_add_msc(self, msc, meta):
        err = self.validate_msc(msc)
        if err:
            msg = ErrorMsg.from_values(err)
            self.send_meta(msg, meta)
            return
        self.mscs_to_add.append(msc)
        self.accept(msc, meta)

    def validate_msc(self, msc):
        """
        Verify MSC and check if it can be added.
        """
        # First check whether MSC already exist
        label = CertificateEntry.from_values(msc).get_label()
        if self.log.cert_tree.get_entry(label):
            return "Entry is logged"
        for tmp in self.mscs_to_add:
            if tmp.pack() == msc.pack():
                return "Entry is scheduled"
        try:
            msc.validate()
        except EEPKIError:
                return "Validation failed"
        # TODO(PSz): extra validation here
        return None

    @try_lock
    def handle_add_rev(self, rev, meta):
        err = self.validate_rev(rev)
        if err:
            msg = ErrorMsg.from_values(err)
            self.send_meta(msg, meta)
            return
        self.revs_to_add.append(rev)
        self.accept(rev, meta)

    def validate_rev(self, rev):
        """
        Verify revocation and check if it can be added.
        """
        return None

    def accept(self, obj, meta):
        hash_ = hash_function(obj.pack()).digest()
        msg = AcceptMsg.from_values(hash_, self.priv_key)
        self.send_meta(msg, meta)

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
            for entry in self.mscs_to_add + self.scps_to_add + self.revs_to_add:
                self.log.add(entry)
            self.log.build()
            self.update_root()
            self.mscs_to_add = []
            self.scps_to_add = []
            self.revs_to_add = []
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
        sys.exit(-1)
    addr = SCIONAddr.from_values(ISD_AS(sys.argv[1]), haddr_parse(1, sys.argv[2]))
    log_serv = LogServer(addr)
    print("running log")
    log_serv.run()
