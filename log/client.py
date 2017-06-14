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
from pki.lib.defines import EEPKI_PORT, EEPKIError
from pki.lib.tree_entries import (
    MSCEntry,
    RevocationEntry,
    SCPEntry,
    )
from pki.log.msg import *

from lib.tcp.socket import SCIONTCPSocket
from lib.packet.host_addr import haddr_parse
from lib.packet.scion_addr import ISD_AS, SCIONAddr
from lib.util import recv_all
from test.integration.base_cli_srv import get_sciond_api_addr
import lib.app.sciond as lib_sciond


class LogClient(object):
    def __init__(self, addr):
        self.addr = addr
        self.sock = SCIONTCPSocket()

    def connect(self, src_addr):
        self.sock.bind((self.addr, 0))
        path_info = self.get_paths_info(src_addr.isd_as)
        if path_info:
            self.sock.connect(src_addr, EEPKI_PORT, *path_info[0])

    def get_paths_info(self, dst_isd_as):
        lib_sciond.init(get_sciond_api_addr(self.addr))
        paths = []
        for reply in lib_sciond.get_paths(dst_isd_as):
            paths.append((reply.path().fwd_path(), reply.first_hop().ipv4(),
                         reply.first_hop().p.port))
        return paths

    def send_msg(self, msg):
        raw = msg.pack()
        self.sock.sendall(struct.pack("!I", len(raw)) + raw)

    def recv_msg(self):
        size = struct.unpack("!I", recv_all(self.sock, 4, 0))[0]
        raw = recv_all(self.sock, size, 0)
        return build_msg(raw)

    def close(self):
        self.sock.close()

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
        assert isinstance(msg, AcceptMsg)
        # FIXME(PSz): app should validate that
        # hash_ = hash_function(obj.pack()).digest()
        # if  hash_ != msg.hash:
        #     logging.error("Incorrect hashes: %s != %s" % (hash_, msg.hash))
        #     return None
        return msg

    def get_root(self):
        req = SignedRoot()
        self.send_msg(req)
        msg = self.recv_msg()
        assert isinstance(msg, SignedRoot)
        return msg

    def get_update(self, entry_from, entry_to):
        req = UpdateMsg.from_values(entry_from, entry_to)
        self.send_msg(req)
        msg = self.recv_msg()
        assert isinstance(msg, UpdateMsg)
        return msg


if __name__ == "__main__":
    if len(sys.argv) != 5:
        print("%s <srcISD-AS> <srcIP> <dstISD-AS> <dstIP>" % sys.argv[0])
        # PYTHONPATH=..:../scion python3 log/client.py 2-25 127.2.2.2 1-17 127.1.1.1
        sys.exit()
    cli_addr = SCIONAddr.from_values(ISD_AS(sys.argv[1]), haddr_parse(1, sys.argv[2]))
    srv_addr = SCIONAddr.from_values(ISD_AS(sys.argv[3]), haddr_parse(1, sys.argv[4]))
    # start client
    cli = LogClient(cli_addr)
    cli.connect(srv_addr)
