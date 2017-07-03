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

from pysyncobj import SyncObj, SyncObjConf, replicated

from .defines import EEPKI_SYNCH_PORT


class ReplicatedList(SyncObj):
    def __init__(self, my_addr, peers):
        cfg = SyncObjConf(dynamicMembershipChange = True)
        super().__init__(my_addr, peers, cfg)
        self.__data = []

    @replicated
    def append(self, elem):
        self.__data.append(elem)

    def get(self, idx):
        return self.__data[idx]

    def get_len(self):
        return len(self.__data)

    def get_data(self):
        return self.__data


class SCPCache(object):
    def __init__(self, my_id, logs):
        my_addr = None
        peers = []
        for id_ in logs:
            addr = "%s:%d" % (logs[id_].addr.host, EEPKI_SYNCH_PORT)
            if id_ == my_id:
                my_addr = addr
            else:
                peers.append(addr)
        self.list = ReplicatedList(my_addr, peers)
        self.last_idx = 0

    def add(self, scp_raw):
        self.list.append(scp_raw)

    def get_new(self):
        len_ = self.list.get_len()
        res = self.list.get_data()[self.last_idx:]
        self.last_idx = len_
        return res
