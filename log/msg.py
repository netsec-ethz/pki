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
import copy
import struct
import time

from pki.lib.defines import EEPKIParseError, EEPKIValidationError, MsgFields as MF
from pki.lib.utils import bin_to_obj, build_obj, obj_to_bin
from pki.lib.tree_entries import build_entry
from pki.lib.tree_proofs import EEPKIProof

from lib.crypto.asymcrypto import sign, verify

class Message(object):
    TYPE = "SHOULDN'T SEE THAT!!!"
    def __init__(self, raw=None):
        if raw:
            self.parse(raw)

    def parse(self, raw):
        dict_ = bin_to_obj(raw)
        if MF.TYPE not in dict_ or dict_[MF.TYPE] != self.TYPE:
            raise EEPKIParseError("Incorrect or no type")
        return dict_

    def pack(self):
        return {MF.TYPE: self.TYPE}

    def pack_full(self):  # Use for transport (consistent with SCION's control plane)
        raw = self.pack()
        return struct.pack("!I", len(raw)) + raw

    def __str__(self):
        return '%s(%s)' % (type(self).__name__,
                           ', '.join('%s=%s' % item for item in sorted(vars(self).items())))

    def __eq__(self, other):
        return self.pack() == other.pack()


class SignedMessage(Message):
    def __init__(self, raw=None):
        self.signature = None
        if raw:
            self.parse(raw)

    def parse(self, raw):
        dict_ = super().parse(raw)
        if MF.SIGNATURE in dict_:
            self.signature = dict_[MF.SIGNATURE]
        return dict_

    def validate(self, pub_key):
        inst = copy.copy(self)
        inst.signature = b""
        if not verify(inst.pack(), self.signature, pub_key):
            raise EEPKIValidationError("Incorrect signature")

    def sign(self, priv_key):
        inst = copy.copy(self)
        inst.signature = b""
        self.signature = sign(inst.pack(), priv_key)


class ErrorMsg(Message):
    TYPE = MF.ERROR_MSG
    def __init__(self, raw=None):
        self.description = None
        super().__init__(raw)

    def parse(self, raw):
        dict_ = super().parse(raw)
        if MF.DESCRIPTION in dict_:
            self.description = dict_[MF.DESCRIPTION]

    def pack(self):
        dict_ = super().pack()
        if self.description:
            dict_[MF.DESCRIPTION] = self.description
        return obj_to_bin(dict_)

    @classmethod
    def from_values(cls, desc):
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
    def from_values(cls, entry):
        inst = cls()
        inst.entry = entry
        return inst


class AcceptMsg(SignedMessage):
    TYPE = MF.ACCEPT_MSG
    def __init__(self, raw=None):
        self.hash = None
        self.timestamp = None
        super().__init__(raw)

    def parse(self, raw):
        dict_ = super().parse(raw)
        if MF.HASH not in dict_ or not dict_[MF.HASH]:
            raise EEPKIParseError("Incomplete message")
        self.hash = dict_[MF.HASH]
        if MF.TIMESTAMP not in dict_ or not dict_[MF.TIMESTAMP]:
            raise EEPKIParseError("Incomplete message")
        self.timestamp = dict_[MF.TIMESTAMP]

    def pack(self):
        dict_ = super().pack()
        dict_[MF.HASH] = self.hash
        dict_[MF.TIMESTAMP] = self.timestamp
        dict_[MF.SIGNATURE] = self.signature
        return obj_to_bin(dict_)

    @classmethod
    def from_values(cls, hash_, priv_key):
        inst = cls()
        inst.hash = hash_
        inst.timestamp = int(time.time())
        inst.sign(priv_key)
        return inst


class UpdateMsg(Message):
    """
    Used for querying and returning updates.
    When queried self.entries is empty.
    """
    TYPE = MF.UPDATE_MSG
    LOG_ID = "log_id"
    def __init__(self, raw=None):
        self.entry_from = None
        self.entry_to = None
        self.entries = []
        self.log_id = None
        super().__init__(raw)

    def parse(self, raw):
        dict_ = super().parse(raw)
        if MF.ENTRY_FROM not in dict_ or MF.ENTRY_TO not in dict_:
            raise EEPKIParseError("Incomplete message")
        try:
            self.entry_from = int(dict_[MF.ENTRY_FROM])
            self.entry_to = int(dict_[MF.ENTRY_TO])
        except TypeError:
            raise EEPKIParseError("Incorrect message")
        if self.LOG_ID in dict_:
            self.log_id = dict_[self.LOG_ID]
        if MF.ENTRIES in dict_:
            for raw_entry in dict_[MF.ENTRIES]:
                self.entries.append(build_entry(raw_entry))

    def pack(self):
        dict_ = super().pack()
        dict_[self.LOG_ID] = self.log_id
        if self.entry_from is None or self.entry_to is None:
            raise EEPKIParseError("Cannot pack")
        dict_[MF.ENTRY_FROM] = self.entry_from
        dict_[MF.ENTRY_TO] = self.entry_to
        if self.entries:
            dict_[MF.ENTRIES] = [entry.pack() for entry in self.entries]
        return obj_to_bin(dict_)

    @classmethod
    def from_values(cls, entry_from, entry_to):
        inst = cls()
        inst.entry_from = entry_from
        inst.entry_to = entry_to
        return inst


class ProofMsg(Message):
    """
    Used for querying and returning proofs.
    When queried self.proof is None.
    """
    TYPE = MF.PROOF_MSG
    def __init__(self, raw=None):
        self.domain_name = None
        self.msc_label = None
        self.eepki_proof = None
        self.append_root = None  # If true the RootMsg is sent (or requested) after ProofMsg
        super().__init__(raw)

    def parse(self, raw):
        dict_ = super().parse(raw)
        if MF.DNAME not in dict_ or not dict_[MF.DNAME]:
            raise EEPKIParseError("Incomplete message")
        self.domain_name = dict_[MF.DNAME]
        if MF.MSC_LABEL not in dict_:
            raise EEPKIParseError("Incomplete message")
        self.msc_label = dict_[MF.MSC_LABEL]
        if MF.EEPKI_PROOF not in dict_:
            raise EEPKIParseError("Incomplete message")
        if dict_[MF.EEPKI_PROOF]:
            self.eepki_proof = EEPKIProof(dict_[MF.EEPKI_PROOF])
        if MF.APPEND_ROOT not in dict_:
            raise EEPKIParseError("Incomplete message")
        if MF.APPEND_ROOT in dict_:
            self.append_root = dict_[MF.APPEND_ROOT]

    def pack(self):
        dict_ = super().pack()
        dict_[MF.DNAME] = self.domain_name
        dict_[MF.MSC_LABEL] = self.msc_label
        dict_[MF.APPEND_ROOT] = self.append_root
        if self.eeepki_proof:
            dict_[MF.EEPKI_PROOF] = self.eepki_proof.pack()
        else:
            dict_[MF.EEPKI_PROOF] = None
        return obj_to_bin(dict_)

    @classmethod
    def from_values(cls, domain_name, msc_label=None, append_root=True):
        inst = cls()
        inst.domain_name = domain_name
        inst.msc_label = msc_label
        inst.eepki_proof = proof
        inst.append_root = append_root
        return inst


class SignedRoot(SignedMessage):
    """
    Used for querying and returning signed roots.
    """
    TYPE = MF.SIGNED_ROOT
    ROOT_IDX = "root_idx"
    LOG_ID = "log_id"
    def __init__(self, raw=None):
        self.root = None
        self.timestamp = None
        self.entries_no = None
        self.root_idx = None
        self.log_id = None
        super().__init__(raw)

    def parse(self, raw):
        dict_ = super().parse(raw)
        if MF.ROOT in dict_:
            self.root = dict_[MF.ROOT]
        if MF.TIMESTAMP in dict_:
            self.timestamp = dict_[MF.TIMESTAMP]
        if MF.ENTRIES_NO in dict_:
            self.entries_no = dict_[MF.ENTRIES_NO]
        if self.ROOT_IDX in dict_:
            self.root_idx = dict_[self.ROOT_IDX]
        if self.LOG_ID in dict_:
            self.log_id = dict_[self.LOG_ID]

    def pack(self):
        dict_ = super().pack()
        dict_[MF.ROOT] = self.root
        dict_[MF.TIMESTAMP] = self.timestamp
        dict_[MF.ENTRIES_NO] = self.entries_no
        dict_[self.ROOT_IDX] = self.root_idx
        dict_[MF.SIGNATURE] = self.signature
        dict_[self.LOG_ID] = self.log_id
        return obj_to_bin(dict_)

    @classmethod
    def from_values(cls, root, root_idx, entries_no, log_id, priv_key):
        inst = cls()
        inst.root = root
        inst.root_idx = root_idx
        inst.entries_no = entries_no
        inst.log_id = log_id
        inst.timestamp = int(time.time())
        inst.sign(priv_key)
        return inst


class RootConfirm(SignedMessage):
    """
    Used for querying and returning monitor confirmations.
    """
    TYPE = MF.ROOT_CONFIRM
    SIGNED_ROOT = "signed_root"
    def __init__(self, raw=None):
        self.signed_root = None
        super().__init__(raw)

    def parse(self, raw):
        dict_ = super().parse(raw)
        if self.SIGNED_ROOT not in dict_:
            raise EEPKIParseError("Incomplete message")
        self.signed_root = SignedRoot(dict_[self.SIGNED_ROOT])

    def pack(self):
        dict_ = super().pack()
        if self.signed_root:
            dict_[self.SIGNED_ROOT] = self.signed_root.pack()
        return obj_to_bin(dict_)

    @classmethod
    def from_values(cls, signed_root, priv_key):
        inst = cls()
        inst.signed_root = signed_root
        inst.sign(priv_key)
        return inst


def build_msg(raw):
    classes = [ErrorMsg, AddMsg, AcceptMsg, UpdateMsg, ProofMsg, SignedRoot, RootConfirm]
    return build_obj(raw, classes)
