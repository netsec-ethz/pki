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

from pki.log.log import Log
from pki.log.elem import EEPKIElement

# SCION
from lib.packet.host_addr import haddr_parse
from lib.packet.scion_addr import ISD_AS, SCIONAddr


class LogServer(EEPKIElement):
    def __init__(self, addr):
        # Init network
        super().__init__(addr)
        # Init log
        self.log = Log()
        self.lock = threading.Lock()

    def init_db(self):
        pass

    def handle_msg_meta(self, msg, meta):
        """
        Main routine to handle incoming SCION messages.
        """
        print("Message and meta to handle: ", msg, meta)

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
