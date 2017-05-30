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
from base64 import b64decode, b64encode

from merkle import check_chain, MerkleError

from .defines import MsgFields
from .utils import dict_to_cbor


class BaseProof(object):
    TYPE = None
    def __init__(self, raw=None):
        self.raw = raw
        if raw is not None:
            self.parse(raw)

    def parse(self, raw):
        raise NotImplementedError

    def pack(self):
        return {MsgFields.TYPE: self.TYPE}

    def validate(self, external_root=None):
        raise NotImplementedError

    def join(self, higher_proof):
        """
        Extend (if possible) the self proof by the higher_proof.
        """
        raise NotImplementedError


class PresenceProof(BaseProof):
    TYPE = MsgFields.PRESENCE_PROOF
    def __init__(self, raw=None):
        self.entry = None
        self.chain = None
        super().__init__(raw)

    def pack(self):
        tmp = super().__pack__()
        # TODO(PSz): other fields + base64
        return dict_to_cbor(tmp)

    @classmethod
    def from_values(cls, entry, chain):
        inst = cls()
        inst.entry, inst.chain = entry, chain
        return inst

    def get_root(self):
        return self.chain[-1][0]

    def get_entry_hash(self):
        """
        Get entry hash from the chain.
        """
        return self.chain[0][0]

    def validate(self, entry=None, external_root=None):
        if not self.entry or not self.chain:
            return False  # Incomplete proof
        if external_root and external_root != self.get_root():
            return False  # Roots mismatch
        if entry and entry.get_hash() != self.entry.get_hash():
            return False  # Proof is constructed for other entry
        if self.get_entry_hash() != self.entry.get_hash():
            return False  # Hash of the entry doesn't match the proof
        try:
            check_chain(self.chain)
        except MerkleError:
            return False  # Chain verification failed
        return True

    def __str__(self):
        return "Entry: %s, Chain: %s" % (self.entry.get_label(), self.chain)


class AbsenceProof(BaseProof):
    """
    """
    TYPE = MsgFields.ABSENCE_PROOF
    def __init__(self, raw=None):
        """
        Absence proof consists of two presence proofs.
        """
        self.proof1 = None
        self.proof2 = None
        super().__init__(raw)

    def validate(self, entry, external_root=None):
        if not self.proof1 and not self.proof2:
            return False  # Incomplete proof
        elif not self.proof1 or not self.proof2:  # Handle cases with one proof
            return self._single_proof(entry, external_root)

        # Handle the common case (two presence proofs)
        if not (self.proof1.entry < entry < self.proof2.entry):  # Entry must be between
            return False
        if not self.proof1.validate(external_root=external_root):
            return False
        if not self.proof2.validate(external_root=external_root):
            return False
        if self.proof1.get_root() != self.proof2.get_root():  # Check if the tree is the
            return False
        if external_root and external_root != self.proof1.get_root():
            return False
        if not self._sibling_proofs():
            return False
        return True

    def _single_proof(self, entry, external_root):
        """
        Single proof validation (corner case).
        """
        if self.proof1:
            if self.proof1.entry <= entry:
                return False
            char = 'L'
            chain = self.proof1.chain
            proof = self.proof1
        else:
            if self.proof1.entry >= entry:
                return False
            char = 'R'
            chain = self.proof1.chain
            proof = self.proof2

        # This has to be the most left or right root
        for _, tmp in chain[1:-1]:  # Don't check 'SELF' and 'ROOT'
            if tmp != char:
                return False
        if not proof.validate(external_root=external_root):
            return False
        return True

    def _sibling_proofs(self):
        # TODO(PSz): ensure that proof1 and proof2 are for the siblings entries
        # Probably, need to add tree size at least
        return True

    def parse(self, raw):
        pass

    def pack(self):
        tmp = super().__pack__()
        # TODO(PSz): other fields + base64
        return dict_to_cbor(tmp)

    @classmethod
    def from_values(cls, proof1, proof2):
        inst = cls()
        inst.proof1 = proof1
        inst.proof2 = proof2
        return inst

    def __str__(self):
        return "Proof1: %s\nProof2: %s" % (self.proof1, self.proof2)


class PolicyProof(BaseProof):
    """
    Complete proof of an SCP. It consists of either of n>0 presence proofs, or a
    single absence proof and N>=0 presence proofs. See... TODO(PSz)
    """
    TYPE = MsgFields.POLICY_PROOF
    def __init__(self, raw=None):
        """
        """
        self.proofs = []
        super().__init__(raw)

    @classmethod
    def from_values(cls, proofs):
        inst = cls()
        inst.proofs = proofs
        return inst

    def __str__(self):
        res = ["PolicyProof"]
        for proof in self.proofs:
            res.append(str(proof))
        return "\n".join(res)
