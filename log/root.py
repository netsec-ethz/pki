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
import time

class SignedRoot(object):
    def __init__(self, raw=None):
        self.root = None
        self.timestamp = None
        self.entries_no = None
        self.signature = None
        if raw:
            self.parse(raw)

    def parse(self, raw):
        raise NotImplementedError

    def pack(self):
        raise NotImplementedError

    @classmethod
    def from_values(root, entries_no, timestamp=None, signature=None):
        inst = cls()
        inst.root = root
        inst.entries_no = entries_no
        inst.timestamp = timestamp
        inst.signature = signature
        return inst

    def verify(self, public_key): 
        raise NotImplementedError

    def sign(self, private_key): 
        if not self.timestamp:
            self.timestamp = int(time.time())
        raise NotImplementedError

