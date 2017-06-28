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
    SIGNATURE = "sig"
    def __init__(self, raw=None):
        self.signature = None
        if raw:
            self.parse(raw)

    def parse(self, raw):
        dict_ = super().parse(raw)
        if self.SIGNATURE in dict_:
            self.signature = dict_[self.SIGNATURE]
        return dict_

    def validate(self, pubkey):
        inst = copy.copy(self)
        inst.signature = b""
        if not verify(inst.pack(), self.signature, pubkey):
            raise EEPKIValidationError("Incorrect signature")
        return True

    def sign(self, privkey):
        inst = copy.copy(self)
        inst.signature = b""
        self.signature = sign(inst.pack(), privkey)

    def pack(self):
        dict_ = super().pack()
        dict_[self.SIGNATURE] = self.signature
        return dict_

class ErrorMsg(Message):
    TYPE = MF.ERROR_MSG
    DESCRIPTION = "desc"
    def __init__(self, raw=None):
        self.description = None
        super().__init__(raw)

    def parse(self, raw):
        dict_ = super().parse(raw)
        if self.DESCRIPTION in dict_:
            self.description = dict_[self.DESCRIPTION]

    def pack(self):
        dict_ = super().pack()
        if self.description:
            dict_[self.DESCRIPTION] = self.description
        return obj_to_bin(dict_)

    @classmethod
    def from_values(cls, desc):
        inst = cls()
        inst.description = desc
        return inst


class AddMsg(Message):
    TYPE = MF.ADD_MSG
    ENTRY = "entry"
    def __init__(self, raw=None):
        self.entry = None
        super().__init__(raw)

    def parse(self, raw):
        dict_ = super().parse(raw)
        if self.ENTRY not in dict_ or not dict_[self.ENTRY]:
            raise EEPKIParseError("Incomplete message")
        self.entry = build_entry(dict_[self.ENTRY])

    def pack(self):
        dict_ = super().pack()
        dict_[self.ENTRY] = self.entry.pack()
        return obj_to_bin(dict_)

    @classmethod
    def from_values(cls, entry):
        inst = cls()
        inst.entry = entry
        return inst


class AcceptMsg(SignedMessage):
    TYPE = MF.ACCEPT_MSG
    HASH = "hash"
    TIMESTAMP = "time"
    def __init__(self, raw=None):
        self.hash = None
        self.timestamp = None
        super().__init__(raw)

    def parse(self, raw):
        dict_ = super().parse(raw)
        if self.HASH not in dict_ or not dict_[self.HASH]:
            raise EEPKIParseError("Incomplete message")
        self.hash = dict_[self.HASH]
        if self.TIMESTAMP not in dict_ or not dict_[self.TIMESTAMP]:
            raise EEPKIParseError("Incomplete message")
        self.timestamp = dict_[self.TIMESTAMP]

    def pack(self):
        dict_ = super().pack()
        dict_[self.HASH] = self.hash
        dict_[self.TIMESTAMP] = self.timestamp
        return obj_to_bin(dict_)

    @classmethod
    def from_values(cls, hash_, privkey):
        inst = cls()
        inst.hash = hash_
        inst.timestamp = int(time.time())
        inst.sign(privkey)
        return inst


class UpdateMsg(Message):
    """
    Used for querying and returning updates.
    When queried self.entries is empty.

    PSz: hash of that message could be signed by a log on every update. Then monitors have
    easier job to manage updates.
    """
    TYPE = MF.UPDATE_MSG
    LOG_ID = "log_id"
    ENTRY_FROM = "from"
    ENTRY_TO = "to"
    ENTRIES = "entries"
    def __init__(self, raw=None):
        self.entry_from = None
        self.entry_to = None
        self.entries = []
        self.log_id = None
        super().__init__(raw)

    def parse(self, raw):
        dict_ = super().parse(raw)
        if self.ENTRY_FROM not in dict_ or self.ENTRY_TO not in dict_:
            raise EEPKIParseError("Incomplete message")
        try:
            self.entry_from = int(dict_[self.ENTRY_FROM])
            self.entry_to = int(dict_[self.ENTRY_TO])
        except TypeError:
            raise EEPKIParseError("Incorrect message")
        if self.LOG_ID in dict_:
            self.log_id = dict_[self.LOG_ID]
        if self.ENTRIES in dict_:
            for raw_entry in dict_[self.ENTRIES]:
                self.entries.append(build_entry(raw_entry))

    def pack(self):
        dict_ = super().pack()
        dict_[self.LOG_ID] = self.log_id
        if self.entry_from is None or self.entry_to is None:
            raise EEPKIParseError("Cannot pack")
        dict_[self.ENTRY_FROM] = self.entry_from
        dict_[self.ENTRY_TO] = self.entry_to
        if self.entries:
            dict_[self.ENTRIES] = [entry.pack() for entry in self.entries]
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
    DNAME = "name"
    MSC_LABEL = "msc"
    EEPKI_PROOF = "proof"
    APPEND_ROOT = "append_root"
    def __init__(self, raw=None):
        self.domain_name = None
        self.msc_label = None
        self.eepki_proof = None
        self.append_root = None  # If true the RootMsg is sent (or requested) after ProofMsg
        super().__init__(raw)

    def parse(self, raw):
        dict_ = super().parse(raw)
        if self.DNAME not in dict_ or not dict_[self.DNAME]:
            raise EEPKIParseError("Incomplete message")
        self.domain_name = dict_[self.DNAME]
        if self.MSC_LABEL not in dict_:
            raise EEPKIParseError("Incomplete message")
        self.msc_label = dict_[self.MSC_LABEL]
        if self.EEPKI_PROOF not in dict_:
            raise EEPKIParseError("Incomplete message")
        if dict_[self.EEPKI_PROOF]:
            self.eepki_proof = EEPKIProof(dict_[self.EEPKI_PROOF])
        if self.APPEND_ROOT not in dict_:
            raise EEPKIParseError("Incomplete message")
        if self.APPEND_ROOT in dict_:
            self.append_root = dict_[self.APPEND_ROOT]

    def pack(self):
        dict_ = super().pack()
        dict_[self.DNAME] = self.domain_name
        dict_[self.MSC_LABEL] = self.msc_label
        dict_[self.APPEND_ROOT] = self.append_root
        if self.eeepki_proof:
            dict_[self.EEPKI_PROOF] = self.eepki_proof.pack()
        else:
            dict_[self.EEPKI_PROOF] = None
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
    ROOT = "root"
    TIMESTAMP = "time"
    ENTRIES_NO = "entries_no"
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
        if self.ROOT in dict_:
            self.root = dict_[self.ROOT]
        if self.TIMESTAMP in dict_:
            self.timestamp = dict_[self.TIMESTAMP]
        if self.ENTRIES_NO in dict_:
            self.entries_no = dict_[self.ENTRIES_NO]
        if self.ROOT_IDX in dict_:
            self.root_idx = dict_[self.ROOT_IDX]
        if self.LOG_ID in dict_:
            self.log_id = dict_[self.LOG_ID]

    def pack(self):
        dict_ = super().pack()
        dict_[self.ROOT] = self.root
        dict_[self.TIMESTAMP] = self.timestamp
        dict_[self.ENTRIES_NO] = self.entries_no
        dict_[self.ROOT_IDX] = self.root_idx
        dict_[self.LOG_ID] = self.log_id
        return obj_to_bin(dict_)

    @classmethod
    def from_values(cls, root, root_idx, entries_no, log_id, privkey):
        inst = cls()
        inst.root = root
        inst.root_idx = root_idx
        inst.entries_no = entries_no
        inst.log_id = log_id
        inst.timestamp = int(time.time())
        inst.sign(privkey)
        return inst


class RootConfirm(SignedMessage):
    """
    Used for querying and returning monitor confirmations.
    """
    TYPE = MF.ROOT_CONFIRM
    SIGNED_ROOT = "signed_root"
    MONITOR_ID = "monitor_id"
    def __init__(self, raw=None):
        self.signed_root = None
        self.monitor_id = None
        super().__init__(raw)

    def parse(self, raw):
        dict_ = super().parse(raw)
        if self.SIGNED_ROOT not in dict_:
            raise EEPKIParseError("Incomplete message")
        self.signed_root = SignedRoot(dict_[self.SIGNED_ROOT])
        if self.MONITOR_ID in dict_:
            self.monitor_id = dict_[self.MONITOR_ID]

    def pack(self):
        dict_ = super().pack()
        if self.signed_root:
            dict_[self.SIGNED_ROOT] = self.signed_root.pack()
        if self.monitor_id is not None:
            dict_[self.MONITOR_ID] = self.monitor_id
        return obj_to_bin(dict_)

    @classmethod
    def from_values(cls, signed_root, monitor_id, privkey):
        inst = cls()
        inst.signed_root = signed_root
        inst.monitor_id = monitor_id
        inst.sign(privkey)
        return inst


class RootConfirmReq(Message):
    TYPE = MF.ROOT_CONFIRM_REQ
    LOG_ID = "log_id"
    ROOT_IDX = "root_idx"
    def __init__(self, raw=None):
        self.log_id = None
        self.root_idx = None
        super().__init__(raw)

    def parse(self, raw):
        dict_ = super().parse(raw)
        if self.LOG_ID not in dict_ or self.ROOT_IDX not in dict_:
            raise EEPKIParseError("Incomplete message")
        self.log_id = dict_[self.LOG_ID]
        self.root_idx = dict_[self.ROOT_IDX]

    def pack(self):
        dict_ = super().pack()
        dict_[self.LOG_ID] = self.log_id
        dict_[self.ROOT_IDX] = self.root_idx
        return obj_to_bin(dict_)

    @classmethod
    def from_values(cls, log_id, root_idx):
        inst = cls()
        inst.log_id = log_id
        inst.root_idx = root_idx
        return inst


def build_msg(raw):
    classes = [ErrorMsg, AddMsg, AcceptMsg, UpdateMsg, ProofMsg,
               SignedRoot, RootConfirm, RootConfirmReq]
    return build_obj(raw, classes)
