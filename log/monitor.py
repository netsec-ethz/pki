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
import threading

from pki.defines import EEPKI_PORT
from pki.log.log import Log
from pki.log.msg import (
    ErrorMsg,
    RootConfirm,
    SignedRoot,
    UpdateMsg,
)

# SCION
from lib.crypto.trc import TRC
from lib.packet.host_addr import haddr_parse
from lib.packet.scion_addr import ISD_AS, SCIONAddr

MONITOR_INTERVAL = 1.0

class LogMonitor(EEPKIElement):
    def __init__(self, addr):
        logging.basicConfig(level=logging.DEBUG, format="%(asctime)-15s %(message)s")
        # Init logs
        self.init_logs()
        # Init network
        super().__init__(addr)

    def init_logs(self):
        # TODO(PSz): read from TRC
        addr = SCIONAddr.from_values(ISD_AS("1-17"), haddr_parse(1, "127.1.1.1"))
        self.log2addr = {'log1': addr}
        for log_id in self.log2addr:
            self.logs[log_id] = Log()
            self.log2log[log_id] = threading.Lock()
            self.signed_roots[log_id] = []

    def handle_msg_meta(self, msg, meta):
        """
        Main routine to handle incoming SCION messages.
        """
        if isinstance(msg, SignedRoot):
            self.handle_root(msg, meta)
        elif isinstance(msg, UpdateMsg):
            self.handle_update(msg, meta)
        elif isinstance(msg, RootConfirm):
            self.handle_confirm_request(msg, meta)
        elif isinstance(msg, ErrorMsg):
            self.handle_error(msg, meta)
        else:
            self.send_error(meta, "No handler for request: %s" % msg)

    def handle_error(self, msg, meta):
        logging.error("Received: %s" % msg)

    def send_error(self, desc, meta):
        msg = ErrorMsg.from_values(desc)
        self.send_meta(msg, meta)

    def handle_root(self, msg, meta):
        pass

    def handle_update(self, msg, meta):
        pass

    def handle_confirm_request(self, msg, meta):
        pass

    def worker(self):
        start = time.time()
        while self.run_flag.is_set():
            sleep_interval(start, self.MONITOR_INTERVAL, "LogServer.worker sleep",
                           self._quiet_startup())
            start = time.time()
            self.ask_for_roots()

    def ask_for_roots(self):
        pass

    def run(self):
        threading.Thread(
            target=thread_safety_net, args=(self.worker,),
            name="LogServer.worker", daemon=True).start()
        super().run()

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("%s <ISD-AS> <IP>" % sys.argv[0])
        # PYTHONPATH=..:../scion python3 log/monitor.py 1-17 127.3.4.5
        sys.exit(-1)
    addr = SCIONAddr.from_values(ISD_AS(sys.argv[1]), haddr_parse(1, sys.argv[2]))
    log_monitor = LogMonitor(addr)
    print("running monitor")
    log_monitor.run()
