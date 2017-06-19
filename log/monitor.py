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

from .log import Log

LOGS2ADDR

class LogMonitor(EEPKIElement):
    def __init__(self, addr):
        logging.basicConfig(level=logging.DEBUG, format="%(asctime)-15s %(message)s")
        # Init logs
        self.init_logs()
        # Init network
        super().__init__(addr)

    def init_logs(self):
        self.logs = {}  # log_id -> Log()
        self.log2lock = {}
        self.signed_roots = {}

    def handle_msg_meta(self, msg, meta):
        """
        Main routine to handle incoming SCION messages.
        """
        if isinstance(msg, SignedRoot):
            self.handle_root(msg, meta)
        elif isinstance(msg, UpdateMsg):
            self.handle_update(msg, meta)
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
