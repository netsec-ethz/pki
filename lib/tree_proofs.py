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

from .defines import EEPKIError, MsgFields
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

    def validate(self, label, external_root=None):
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

    def validate(self, label, external_root=None):
        if not self.entry or not self.chain:
            raise EEPKIError("Incomplete proof")
        if label != self.entry.get_label():
            raise EEPKIError("Labels mismatch")
        if external_root and external_root != self.get_root():
            raise EEPKIError("Roots mismatch")
        if self.get_entry_hash() != self.entry.get_hash():
            raise EEPKIError("Hash of the entry doesn't match the proof")
        try:
            check_chain(self.chain)
        except MerkleError:
            raise EEPKIError("Chain verification failed")
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

    def validate(self, label, external_root=None):
        if not self.proof1 and not self.proof2:
            raise EEPKIError("Incomplete proof")
        elif not self.proof1 or not self.proof2:  # Handle cases with one proof
            return self._single_proof(label, external_root)

        # Handle the common case (two presence proofs)
        if not (self.proof1.entry.get_label() < label < self.proof2.entry.get_label()):
            raise EEPKIError("Label not between proof1 and proof2")
        if not self.proof1.validate(external_root=external_root):
            raise EEPKIError("Validation of proof1 failed")
        if not self.proof2.validate(external_root=external_root):
            raise EEPKIError("Validation of proof2 failed")
        if self.proof1.get_root() != self.proof2.get_root():
            raise EEPKIError("Proofs have different roots")
        if external_root and external_root != self.proof1.get_root():
            raise EEPKIError("External root mismatch")
        if not self._sibling_proofs():
            raise EEPKIError("Non-siblings proofs")
        return True

    def _single_proof(self, label, external_root):
        """
        Single proof validation (corner case).
        """
        if self.proof1:
            if self.proof1.entry.get_label() <= label:
                raise EEPKIError("Single proof incorrect")
            char = 'L'
            chain = self.proof1.chain
            proof = self.proof1
        else:
            if self.proof1.entry.get_label() >= label:
                raise EEPKIError("Single proof incorrect")
            char = 'R'
            chain = self.proof1.chain
            proof = self.proof2

        # This has to be the most left or right root
        for _, tmp in chain[1:-1]:  # Don't check 'SELF' and 'ROOT'
            if tmp != char:
                raise EEPKIError("Non-boundary proof")
        if not proof.validate(external_root=external_root):
            raise EEPKIError("Validation of proof failed")
        return True

    def _sibling_proofs(self):
        if len(self.proof1.chain) != len(self.proof2.chain):
            raise EEPKIError("Proofs lengths mismatch")
        if self.proof1.get_root() != self.proof2.get_root():
            raise EEPKIError("Roots mismatch")
        int_len = len(self.proof1.chain) - 2  # length without 'SELF' and 'ROOT'
        # Start from the top, to check number of the identitcal nodes (i.e., where paths
        # converge)
        while int_len >= 1:
            if self.proof1.chain[int_len] != self.proof2.chain[int_len]:
                break
            int_len -= 1
        if int_len == 1:
            raise EEPKIError("All intermediate nodes are identical")
        while int_len >= 1:
            if self.proof1.chain[int_len][1] == self.proof2.chain[int_len][1]:
                raise EEPKIError("The same direction on divergent paths")
            int_len -= 1
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


class EEPKIProof(BaseProof):
    """
    Complete proof of MSC and SCP. For SPC's absence proofs an MSC proof can be None.
    """
    TYPE = MsgFields.EEPKI_PROOF
    def __init__(self, raw=None):
        self.cons_proof = None  # ConsistencyTree's proof
        self.policy_proof = None  # PolicyTree's proof
        self.cert_proof = None  # CertificateTree's proof
        super().__init__(raw)

    @classmethod
    def from_values(cls, cons_proof, policy_proof, cert_proof=None):
        inst = cls()
        inst.cons_proof = cons_proof
        inst.policy_proof = policy_proof
        inst.cert_proof = cert_proof
        return inst

    def __str__(self):
        res = ["EEPKIProof:"]
        res.append(str(self.cons_proof))
        res.append(str(self.policy_proof))
        res.append(str(self.cert_proof))
        return "\n".join(res)
