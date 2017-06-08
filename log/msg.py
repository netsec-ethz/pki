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

from pki.lib.defines import EEPKIParseError, MsgFields as MF
from pki.lib.utils import bin_to_obj, obj_to_bin
from pki.lib.tree_entries import build_entry
from pki.lib.tree_proofs import EEPKIProof

class Message(object):
    TYPE = "SHOULDN'T SEE THAT!!!"
    def __init__(self, raw=None):
        if raw:
            self.parse(raw)

    def parse(self, raw):
        dict_ = bin_to_obj(raw)
        if MF.TYPE not in dict_ or dict_[MF.TYPE] != self.TYPE:
            raise EEPKIParseError("No or incorrect type")
        return dict_

    def pack(self):
        return {MF.TYPE: self.TYPE}

    def verify(self, public_key):
        raise NotImplementedError

    def sign(self, private_key):
        raise NotImplementedError


class ErrorMsg(Message):
    TYPE = MF.ERROR_MSG
    def __init__(self, raw=None):
        self.description = None
        super().__init__(raw)

    def parse(self, raw):
        dict_ = super().parse(raw)
        if MF.DESCRIPTION not in dict_ or not dict_[MF.DESCRIPTION]:
            raise EEPKIParseError("Incomplete message")
        self.description = dict_[MF.DESCRIPTION]

    def pack(self):
        dict_ = super().pack()
        dict_[MF.DESCRIPTION] = self.description
        return obj_to_bin(dict_)

    @classmethod
    def from_values(desc):
        inst = cls()
        inst.description = desc
        return inst


class AddMsg(Message):
    TYPE = MF.ADD_MSG
    def __init__(self, raw=None):
        self.entry = None
        super().__init__(raw)

    def parse(self, raw):
        dict_ = super().parse(raw)
        if MF.ENTRY not in dict_ or not dict_[MF.ENTRY]:
            raise EEPKIParseError("Incomplete message")
        self.entry = build_entry(dict_[MF.ENTRY])

    def pack(self):
        dict_ = super().pack()
        dict_[MF.ENTRY] = self.entry.pack() 
        return obj_to_bin(dict_)

    @classmethod
    def from_values(entry):
        inst = cls()
        inst.entry = entry
        return inst


class AcceptMsg(Message):
    TYPE = MF.ACCEPT_MSG
    def __init__(self, raw=None):
        self.hash = None
        self.timestamp = None
        self.signature = None
        super().__init__(raw)

    def parse(self, raw):
        dict_ = super().parse(raw)
        if MF.HASH not in dict_ or not dict_[MF.HASH]:
            raise EEPKIParseError("Incomplete message")
        self.hash = build_HASH(dict_[MF.HASH])
        if MF.TIMESTAMP not in dict_ or not dict_[MF.TIMESTAMP]:
            raise EEPKIParseError("Incomplete message")
        self.timestamp = build_TIMESTAMP(dict_[MF.TIMESTAMP])
        if MF.SIGNATURE not in dict_ or not dict_[MF.SIGNATURE]:
            raise EEPKIParseError("Incomplete message")
        self.signature = build_SIGNATURE(dict_[MF.SIGNATURE])

    def pack(self):
        dict_ = super().pack()
        # entry
        return obj_to_bin(dict_)

    def verify(self, public_key):
        raise NotImplementedError

    def sign(self, private_key):
        self.timestamp = int(time.time())
        # sign here
        raise NotImplementedError

    @classmethod
    def from_values(hash):
        inst = cls()
        self.hash = hash
        return inst


class UpdateMsg(Message):
    """
    Used for querying and returing updates.
    When queried self.entries is empty.
    """
    TYPE = MF.UPDATE_MSG
    def __init__(self, raw=None):
        super().__init__(raw)

    def parse(self, raw):
        dict_ = super().parse(raw)

    def pack(self):
        dict_ = super().pack()
        # entry
        return obj_to_bin(dict_)

    @classmethod
    def from_values():
        inst = cls()
        return inst


class ProofMsg(Message):
    """
    Used for querying and returing proofs.
    When queried self.proof is None.
    """
    TYPE = MF.PROOF_MSG
    def __init__(self, raw=None):
        super().__init__(raw)

    def parse(self, raw):
        dict_ = super().parse(raw)

    def pack(self):
        dict_ = super().pack()
        # entry
        return obj_to_bin(dict_)

    @classmethod
    def from_values():
        inst = cls()
        return inst


class SignedRoot(Message):
    TYPE = MF.SIGNED_ROOT
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

def build_msg(raw):
    raise NotImplementedError
