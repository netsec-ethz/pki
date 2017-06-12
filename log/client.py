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

from pki.lib.defines import EEPKI_PORT
from pki.log.msg import *

from lib.tcp.socket import SCIONTCPSocket
from lib.packet.host_addr import haddr_parse
from lib.packet.scion_addr import ISD_AS, SCIONAddr
from lib.util import recv_all
from test.integration.base_cli_srv import get_sciond_api_addr
import lib.app.sciond as lib_sciond


s_isd_as = ISD_AS("1-17")
s_ip = haddr_parse(1, "127.1.1.1")
c_isd_as = ISD_AS("2-25")
c_ip = haddr_parse(1, "127.2.2.2")

class Client(object):
    def __init__(self, addr, srv_addr):
        self.addr = addr
        self.src_addr = srv_addr
        self.sock = SCIONTCPSocket()

    def connect(self):
        self.sock.bind((self.addr, 0))
        path_info = self.get_paths_info(self.src_addr.isd_as)
        if path_info:
            self.sock.connect(self.src_addr, EEPKI_PORT, *path_info[0])

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


if __name__ == "__main__":
    cli = Client(SCIONAddr.from_values(c_isd_as, c_ip), SCIONAddr.from_values(s_isd_as, s_ip))
    cli.connect()
    msg = UpdateMsg.from_values(1, 1)
    cli.send_msg(msg)
