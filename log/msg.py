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

from pki.lib.defines import MsgFields
from pki.lib.utils import bin_to_obj, obj_to_bin

class Message(object):
    TYPE = "SHOULDN'T SEE THAT!!!"
    def __init__(self, raw=None):
        if raw:
            self.parse(raw)

    def parse(self, raw):
        dict_ = bin_to_obj(raw)
        if MsgFields.TYPE not in dict_ or dict_[MsgFields.TYPE] != self.TYPE:
            raise EEPKIParseError("No or incorrect type")
        return dict_

    def pack(self):
        return {MsgFields.TYPE: self.TYPE}

    def verify(self, public_key):
        raise NotImplementedError

    def sign(self, private_key):
        raise NotImplementedError


class ErrorMsg(Message):
    TYPE = MsgFields.ERROR_MSG
    def __init__(self, raw=None):
        super().__init__(raw)

    def parse(self, raw):
        dict_ = super().parse(raw)

    def pack(self):
        dict_ = super().pack()
        return obj_to_bin(dict_)


class AddMsg(Message):
    TYPE = MsgFields.ADD_MSG
    def __init__(self, raw=None):
        super().__init__(raw)

    def parse(self, raw):
        dict_ = super().parse(raw)

    def pack(self):
        dict_ = super().pack()
        # entry
        return obj_to_bin(dict_)


class AcceptMsg(Message):
    TYPE = MsgFields.ACCEPT_MSG
    def __init__(self, raw=None):
        super().__init__(raw)

    def parse(self, raw):
        dict_ = super().parse(raw)

    def pack(self):
        dict_ = super().pack()
        # entry
        return obj_to_bin(dict_)

    def verify(self, public_key):
        raise NotImplementedError

    def sign(self, private_key):
        if not self.timestamp:
            self.timestamp = int(time.time())
        raise NotImplementedError


class UpdateMsg(Message):
    """
    Used for querying and returing updates.
    When queried self.entries is empty.
    """
    TYPE = MsgFields.UPDATE_MSG
    def __init__(self, raw=None):
        super().__init__(raw)

    def parse(self, raw):
        dict_ = super().parse(raw)

    def pack(self):
        dict_ = super().pack()
        # entry
        return obj_to_bin(dict_)


class ProofMsg(Message):
    """
    Used for querying and returing proofs.
    When queried self.proof is None.
    """
    TYPE = MsgFields.PROOF_MSG
    def __init__(self, raw=None):
        super().__init__(raw)

    def parse(self, raw):
        dict_ = super().parse(raw)

    def pack(self):
        dict_ = super().pack()
        # entry
        return obj_to_bin(dict_)


class SignedRoot(Message):
    TYPE = MsgFields.SIGNED_ROOT
    def __init__(self, raw=None):
        self.root = None
        self.timestamp = None
        self.entries_no = None
        self.signature = None
        super().__init__(raw)

    def parse(self, raw):
        dict_ = super().parse(raw)

    def pack(self):
        dict_ = super().pack()
        return obj_to_bin(dict_)

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
