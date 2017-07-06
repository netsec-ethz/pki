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
import cbor
from nacl.signing import SigningKey

from lib.packet.host_addr import haddr_parse
from lib.packet.scion_addr import ISD_AS, SCIONAddr


class ConfElem(object):
    def __init__(self, isd_as, ip, pubkey):
        self.addr = SCIONAddr.from_values(ISD_AS(isd_as), haddr_parse(1, ip))
        self.pubkey = pubkey


class Conf(object):
    # TODO(PSz): conf_file should be replaced by TRC when it is ready
    def __init__(self, conf_file, privkey_file=None, elem_id=None):
        self.my_id = elem_id
        with open(conf_file, "rb") as f:
            dict_ = cbor.loads(f.read())
        self.threshold = dict_["threshold"]

        self.logs = {}
        for log_id in dict_["logs"]:
            self.logs[log_id] = ConfElem(*dict_["logs"][log_id])

        self.monitors = {}
        for monitor_id in dict_["monitors"]:
            self.monitors[monitor_id] = ConfElem(*dict_["monitors"][monitor_id])

        self.privkey = None
        if privkey_file:
            with open(privkey_file, "rb") as f:
                self.privkey = SigningKey(f.read())

    def get_addr(self, id_=None):
        if id_ is None:
            id_ = self.my_id
        try:
            return {**self.logs, **self.monitors}[id_].addr
        except KeyError:
            return None

    def get_pubkey(self, id_=None):
        if id_ is None:
            id_ = self.my_id
        try:
            return {**self.logs, **self.monitors}[id_].pubkey
        except KeyError:
            return None

    def get_addr_pubkey(self, id_=None):
        if id_ is None:
            id_ = self.my_id
        return self.get_addr(id_), self.get_pubkey(id_)
