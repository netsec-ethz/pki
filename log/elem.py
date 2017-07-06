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
import queue
import threading
import time

from pki.lib.defines import EEPKI_PORT
from pki.lib.msg import build_msg
from pki.log.conf import Conf

from scion_elem.scion_elem import SCIONElement
from lib.socket import SocketMgr
from lib.msg_meta import TCPMetadata


class EEPKIElement(SCIONElement):
    """
    Base class for EEPKI servers.
    """
    USE_TCP = True
    def __init__(self, conf_file, priv_key_file, my_id):
        logging.basicConfig(level=logging.DEBUG, format="%(asctime)-15s %(message)s")
        # First configuration
        self.conf = Conf(conf_file, priv_key_file, my_id)
        # Only relevant stuff from SCIONElement
        self.addr = self.conf.get_addr()
        self._port = EEPKI_PORT
        self.run_flag = threading.Event()
        self.run_flag.set()
        self.stopped_flag = threading.Event()
        self.stopped_flag.clear()
        self._in_buf = queue.Queue()
        self._socks = SocketMgr()
        self.bind = None
        self._setup_sockets(True)
        self._startup = time.time()
        self._DefaultMeta = TCPMetadata
        self._msg_parser = build_msg
        self.ifid2br = {}  # FIXME(PSz): that shouldn't be needed
        self._labels = None
