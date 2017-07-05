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
import struct
import sys

from merkle import hash_function

from pki.lib.cert import MSC, SCP, Revocation
from pki.lib.defines import (
    CONF_DIR,
    CONF_FILE,
    EEPKI_PORT,
    EEPKIError,
    EEPKIValidationError,
    OUTPUT_DIR,
)
from pki.lib.msg import *
from pki.lib.tree_entries import (
    MSCEntry,
    RevocationEntry,
    SCPEntry,
)
from pki.log.conf import Conf
from pki.log.monitor import LogMonitor

import lib.app.sciond as lib_sciond
from lib.tcp.socket import SCIONTCPSocket
from lib.packet.host_addr import haddr_parse
from lib.packet.scion_addr import ISD_AS, SCIONAddr
from lib.util import recv_all
from test.integration.base_cli_srv import get_sciond_api_addr


class LogClient(object):
    def __init__(self, addr, conf_file):
        self.addr = addr
        self.sock = None
        self.pubkey = None  # Log/Monitor's public key
        self.conf = Conf(conf_file)

    def connect(self, dst_id):
        dst_addr, self.pubkey = self.conf.get_addr_pubkey(dst_id)
        self.sock = SCIONTCPSocket()
        self.sock.bind((self.addr, 0))
        path_info = self.get_paths_info(dst_addr.isd_as)
        if path_info:
            self.sock.connect(dst_addr, EEPKI_PORT, *path_info[0])

    def get_paths_info(self, dst_isd_as):
        lib_sciond.init(get_sciond_api_addr(self.addr))
        paths = []
        for reply in lib_sciond.get_paths(dst_isd_as):
            paths.append((reply.path().fwd_path(), reply.first_hop().ipv4(),
                         reply.first_hop().p.port))
        return paths

    def send_msg(self, msg):
        self.sock.sendall(msg.pack_full())

    def recv_msg(self):
        size = struct.unpack("!I", recv_all(self.sock, 4, 0))[0]
        raw = recv_all(self.sock, size, 0)
        return build_msg(raw)

    def close(self):
        self.sock.close()
        self.sock = None

    def get_proof_root(self, scp_label, msc_label=None, append_root=True):
        req = ProofMsg.from_values(scp_label, msc_label, append_root)
        self.send_msg(req)
        proof_msg = self.recv_msg()
        assert isinstance(proof_msg, ProofMsg)
        root_msg = None
        if append_root:
            root_msg = self.recv_msg()
            assert isinstance(root_msg, SignedRoot)
        return (proof_msg, root_msg)

    def submit(self, obj):
        if isinstance(obj, MSC):
            entry = MSCEntry.from_values(obj)
        elif isinstance(obj, SCP):
            entry = SCPEntry.from_values(obj)
        elif isinstance(obj, Revocation):
            entry = RevocationEntry.from_values(obj)
        else:
            raise EEPKIError("Object not supported: %s" % obj)
        req = AddMsg.from_values(entry)
        self.send_msg(req)
        msg = self.recv_msg()
        if isinstance(msg, AcceptMsg):
            msg.validate(self.pubkey)
            # TODO(PSz): check freshness here?
            hash_ = hash_function(obj.pack()).digest()
            if  hash_ != msg.hash:
                raise EEPKIError("Incorrect hashes: %s != %s" % (hash_, msg.hash))
        elif isinstance(msg, ErrorMsg):
            raise EEPKIError(msg.description)
        else:
            raise EEPKIError("Unsupported response")
        return msg

    def get_root(self):
        req = SignedRoot()
        self.send_msg(req)
        msg = self.recv_msg()
        if isinstance(msg, SignedRoot):
            msg.validate(self.pubkey)
            # TODO(PSz): check freshness here?
            return msg
        elif isinstance(msg, ErrorMsg):
            raise EEPKIError(msg.description)
        raise EEPKIError("Unsupported response")

    def get_update(self, entry_from, entry_to):
        req = UpdateMsg.from_values(entry_from, entry_to)
        self.send_msg(req)
        msg = self.recv_msg()
        if isinstance(msg, UpdateMsg):
            return msg
        elif isinstance(msg, ErrorMsg):
            raise EEPKIError(msg.description)
        raise EEPKIError("Unsupported response")

    def confirm_root(self, root):
        req = RootConfirmReq.from_values(root.log_id, root.root_idx)
        self.send_msg(req)
        msg = self.recv_msg()
        if isinstance(msg, RootConfirm):
            msg.validate(self.pubkey)
            # TODO(PSz): check freshness here?
            if root != msg.signed_root:
                raise EEPKIValidationError("Roots mismatch: %s != %s" % (root, msg.root))
            return msg
        elif isinstance(msg, ErrorMsg):
            raise EEPKIError(msg.description)
        raise EEPKIError("Unsupported response")

    def get_and_confirm_root(self, log_id, monitors):
        # connect to a log and get its root
        cli.connect(log_id)
        root = cli.get_root()
        cli.close()
        # connect to monitor(s) and confirm the root
        for monitor_id in monitors:
            cli.connect(monitor_id)
            print(cli.confirm_root(root), end="\n\n")
            cli.close()


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("%s <srcISD-AS> <srcIP> <log_id> <monitor_id> [<monitor_id> ...]" % sys.argv[0])
        # PYTHONPATH=..:../scion python3 log/client.py 2-25 127.2.2.2 log1 monitor1 monitor2 monitor3
        sys.exit(-1)

    import random
    from pki.test.basic_tests import load_mscs_scps
    addr = SCIONAddr.from_values(ISD_AS(sys.argv[1]), haddr_parse(1, sys.argv[2]))
    conf_file = OUTPUT_DIR + CONF_DIR + CONF_FILE
    # start client
    cli = LogClient(addr, conf_file)
    # take sample MSCs and SCPs and try to register them with random log
    mscs, scps = load_mscs_scps()
    mscs = list(mscs.values())
    scps = list(scps.values())
    rnd_log = random.choice(list(cli.conf.logs))
    print("Connecting to %s" % rnd_log)
    cli.connect(rnd_log)
    all_ = scps + mscs
    random.shuffle(all_)
    print("Submitting SCPs and MSCs to %s" % rnd_log)
    i = 1
    for obj in all_:
        print(i, cli.submit(obj))
        i += 1
    cli.close()
    # take every log's root (in random order) and confirm it by all monitors (in random order)
    logs = list(cli.conf.logs)
    random.shuffle(logs)
    monitors = list(cli.conf.monitors)
    random.shuffle(monitors)
    for log_id in logs: 
        cli.get_and_confirm_root(log_id, monitors)
