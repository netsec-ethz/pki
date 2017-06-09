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

from pki.lib.defines import EEPKI_PORT
from .msg import build_msg
from lib.scion.infrastructure.scion_elem import SCIONElement


class EEPKIElement(SCIONElement):
    """
    Base class for EEPKI servers.
    """
    USE_TCP = True
    def __init__(self, addr):
        # Only relevant stuff from SCIONElement
        self.addr = addr
        self._port = EEPKI_PORT
        self.run_flag = threading.Event()
        self.run_flag.set()
        self.stopped_flag = threading.Event()
        self.stopped_flag.clear()
        self._in_buf = queue.Queue(MAX_QUEUE)
        self._socks = SocketMgr()
        self._setup_sockets(True)
        self._startup = time.time()
        if self.USE_TCP:
            self._DefaultMeta = TCPMetadata
        else:
            self._DefaultMeta = UDPMetadata
        self._msg_parser = build_msg
