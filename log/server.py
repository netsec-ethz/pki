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
import queue
import time
import threading
from merkle import hash_function

from pki.lib.defines import CONF_DIR, CONF_FILE, OUTPUT_DIR
from pki.lib.msg import (
    AcceptMsg,
    AddMsg,
    ErrorMsg,
    ProofMsg,
    SignedRoot,
    UpdateMsg,
)
from pki.lib.scp_cache import SCPCache
from pki.lib.tree_entries import (
    CertificateEntry,
    MSCEntry,
    RevocationEntry,
    RootsEntry,
    SCPEntry,
)
from pki.log.elem import EEPKIElement
from pki.log.log import Log

# SCION
from lib.packet.host_addr import haddr_parse
from lib.packet.scion_addr import ISD_AS, SCIONAddr
from lib.thread import thread_safety_net
from lib.util import sleep_interval


def try_lock(handler):
    def wrapper(inst, obj, meta):
        # TODO(PSz): for now just wait when log is under an update (can be optimized
        # with computing log in the memory and replacing the instance)
        with inst.lock:
            handler(inst, obj, meta)
        # if not inst.lock.acquire(blocking=False):
        #     inst.send_error("Service temporarily unavailable", meta)
        #     return
        # handler(inst, obj, meta)
        # inst.lock.release()
    return wrapper


class LogServer(EEPKIElement):
    UPDATE_INTERVAL = 10  # FIXME(PSz): so low for testing
    WORKER_INTERVAL = 0.1
    def __init__(self, conf_file, priv_key_file, my_id):
        # Init configuration and network
        super().__init__(conf_file, priv_key_file, my_id)
        # Init log
        entries = self.init_db()
        self.log = Log(entries)
        self.lock = threading.Lock()
        self.revs_to_add = []
        self.mscs_to_add = []
        self.scps_to_add = []  # TODO(PSz): with the latest change it has to be thread-safe
        self.incoming_scps = Queue()
        self.waiting_scps = []  # TODO(PSz): that should be expiring
        self.signed_roots = []
        self.update_root()
        # Init replicated cache
        self.scp_cache = SCPCache(self.conf.my_id, self.conf.logs)

    def init_db(self):
        return []

    def update_root(self):
        root, entries_no = self.log.get_root_entries()
        root_idx = len(self.signed_roots)
        self.signed_roots.append(SignedRoot.from_values(root, root_idx, entries_no,
                                                        self.conf.my_id, self.conf.privkey))

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
                self.send_error("No handler for entry", meta)
        else:
            self.send_error("No handler for request", meta)

    def send_error(self, desc, meta):
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
            self.send_error("No root for index %d" % idx, meta)

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
        msg.log_id = self.conf.my_id
        self.send_meta(msg, meta)

    @try_lock
    def handle_add_scp(self, scp, meta):
        err = self.validate_scp(scp)
        if err:
            msg = ErrorMsg.from_values(err)
            self.send_meta(msg, meta)
            return
        self.incoming_scps.put(scp)
        # self.scps_to_add.append(scp)
        # self.accept(scp, meta)

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
        msg = AcceptMsg.from_values(hash_, self.conf.privkey)
        self.send_meta(msg, meta)

    def worker(self):
        start = time.time()
        last_update = start
        while self.run_flag.is_set():
            sleep_interval(start, self.WORKER_INTERVAL, "LogServer.worker sleep",
                           self._quiet_startup())
            if time.time() - last_update > self.UPDATE_INTERVAL:
                self.update()
                last_update = time.time()
            self.handle_scps()
            start = time.time()

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

    def handle_scps(self):
        # First, drain the queue and replicate the elements
        while not self.incoming_scps.empty():
            self.scp_cache.add(self.incoming_scps.get_nowait())
            self.waiting_scps.append((scp, meta))
        scps = self.scp_cache.get_new()
        for scp in scps:
            meta = self.get_meta_for_scp(scp) 
            err = self.validate_scp(scp)
            if err:
                if not meta:
                    logging.error("Cannot validate SCP: %s\n%s" % (err, scp))
                    return
                msg = ErrorMsg.from_values(err)
                self.send_meta(msg, meta)
                self.waiting_scps.remove((scp, meta))
                return
            self.scps_to_add.append(scp)
            if meta:
                self.accept(scp, meta)
                self.waiting_scps.remove((scp, meta))

    def get_meta_for_scp(self, scp):
        for scp_wait, meta in self.waiting_scps:
            if scp.pack() == scp_wait.pack():
                return meta
        return None

    def run(self):
        threading.Thread(
            target=thread_safety_net, args=(self.worker,),
            name="LogServer.worker", daemon=True).start()
        super().run()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("%s log_id" % sys.argv[0])
        # PYTHONPATH=..:../scion python3 log/server.py log1
        sys.exit(-1)
    id_ = sys.argv[1]
    conf_file = OUTPUT_DIR + CONF_DIR + CONF_FILE
    priv_key_file = OUTPUT_DIR + CONF_DIR + id_ + ".priv"
    log_serv = LogServer(conf_file, priv_key_file, id_)
    print("running log")
    log_serv.run()
