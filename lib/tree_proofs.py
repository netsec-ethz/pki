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

from .defines import EEPKIError, EEPKIParseError, MsgFields
from .tree_entries import RootsEntry, build_entry
from .utils import bin_to_obj, obj_to_bin, get_domains


class BaseProof(object):
    TYPE = "SHOULDN'T SEE THAT!!!"
    def __init__(self, raw=None):
        self.raw = raw
        if raw is not None:
            self.parse(raw)

    # FIXME(PSz): introduce some base class, parse() and pack() are the same as in entries
    def parse(self, raw):
        dict_ = bin_to_obj(raw)
        if MsgFields.TYPE not in dict_ or dict_[MsgFields.TYPE] != self.TYPE:
            raise EEPKIParseError("No or incorrect type")
        return dict_

    def pack(self):
        return {MsgFields.TYPE: self.TYPE}

    def get_root(self):
        raise NotImplementedError

    def validate(self, label, root):
        if root != self.get_root():
            raise EEPKIError("External root mismatch")

    def get_type(self):
        return self.TYPE


class PresenceProof(BaseProof):
    TYPE = MsgFields.PRESENCE_PROOF
    def __init__(self, raw=None):
        self.entry = None
        self.chain = None
        super().__init__(raw)

    def parse(self, raw):
        dict_ = super().parse(raw)
        if len(dict_) != 3:  # FIXME(PSz): other parse()s need that as well.
            raise EEPKIParseError("#keys != 3")
        if MsgFields.CHAIN not in dict_:
            raise EEPKIParseError("CHAIN not provided")
        self.chain = dict_[MsgFields.CHAIN]
        del dict_[MsgFields.CHAIN]
        # Get entry
        type_, raw = dict_.popitem()
        self.entry = build_entry(raw)

    def pack(self):
        dict_ = super().pack()
        dict_[self.entry.get_type()] = self.entry.pack()
        dict_[MsgFields.CHAIN] = self.chain
        return obj_to_bin(dict_)

    @classmethod
    def from_values(cls, entry, chain):
        inst = cls()
        inst.entry = entry
        inst.chain = chain
        return inst

    def get_root(self):
        return self.chain[-1][0]

    def get_entry_hash(self):
        """
        Get entry hash from the chain.
        """
        return self.chain[0][0]

    def validate(self, label, root):
        super().validate(label, root)
        if not self.entry or not self.chain:
            raise EEPKIError("Incomplete proof")
        if label and label != self.entry.get_label():
            raise EEPKIError("Labels mismatch")
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

    def parse(self, raw):
        dict_ = super().parse(raw)
        print(dict_)
        if len(dict_) != 3:
            raise EEPKIParseError("#keys != 2")
        if MsgFields.PROOF1 not in dict_:
            raise EEPKIParseError("PROOF1 not provided")
        if dict_[MsgFields.PROOF1]:
            self.proof1 = PresenceProof(dict_[MsgFields.PROOF1])
        if MsgFields.PROOF2 not in dict_:
            raise EEPKIParseError("PROOF2 not provided")
        if dict_[MsgFields.PROOF2]:
            self.proof2 = PresenceProof(dict_[MsgFields.PROOF2])

    def pack(self):
        dict_ = super().pack()
        if self.proof1:
            dict_[MsgFields.PROOF1] = self.proof1.pack()
        else:
            dict_[MsgFields.PROOF1] = None
        if self.proof2:
            dict_[MsgFields.PROOF2] = self.proof2.pack()
        else:
            dict_[MsgFields.PROOF2] = None
        return obj_to_bin(dict_)

    @classmethod
    def from_values(cls, proof1, proof2):
        inst = cls()
        inst.proof1 = proof1
        inst.proof2 = proof2
        return inst

    def get_root(self):
        if self.proof1 and self.proof2:
            if self.proof1.get_root() != self.proof2.get_root():
                raise EEPKIError("Proof1 and proof2 have different roots")
            return self.proof1.get_root()
        if self.proof1:  # single proof1
            return self.proof1.get_root()
        elif self.proof2:
            return self.proof2.get_root()  # single proof2
        raise EEPKIError("Cannot get root of None proofs")

    def validate(self, label, root):
        if not self.proof1 and not self.proof2:
            raise EEPKIError("Incomplete proof")
        super().validate(label, root)
        if not self.proof1 or not self.proof2:  # Handle cases with one proof
            return self._single_proof(label, root)

        # Handle the common case (two presence proofs)
        if not (self.proof1.entry.get_label() < label < self.proof2.entry.get_label()):
            raise EEPKIError("Label not between proof1 and proof2")
        if not self.proof1.validate(None, root):
            raise EEPKIError("Validation of proof1 failed")
        if not self.proof2.validate(None, root):
            raise EEPKIError("Validation of proof2 failed")
        if not self._sibling_proofs():
            raise EEPKIError("Non-siblings proofs")
        return True

    def _single_proof(self, label, root):
        """
        Single proof validation (corner case).
        """
        if self.proof1:
            proof = self.proof1
            char = 'L'
            if label <= proof.entry.get_label():
                raise EEPKIError("Single proof1 incorrect")
        else:
            proof = self.proof2
            char = 'R'
            if label >= proof.entry.get_label():
                raise EEPKIError("Single proof2 incorrect")

        # This has to be the most left or right root
        for _, tmp in proof.chain[1:-1]:  # Don't check 'SELF' and 'ROOT'
            if tmp != char:
                raise EEPKIError("Non-boundary proof")
        if not proof.validate(None, root):
            raise EEPKIError("Validation of proof failed")
        return True

    def _sibling_proofs(self):
        # TODO(PSz): this is tree specific. Check how merkle.py handles trees with
        # len(leaves) != 2^x. It may be necessary to add id for proof{1,2} and tree length
        # to check whether they are indeed siblings. With 2^x trees it can be asserted
        # that chains lengths are the same.

        # Minimum over chain lengths without 'SELF'
        int_len = min(len(self.proof1.chain), len(self.proof2.chain)) - 1
        # Start from the top, to check number of the identitcal nodes (i.e., where paths
        # converge)
        while int_len >= 1:
            if self.proof1.chain[-int_len] == self.proof2.chain[-int_len]:
                break
            int_len -= 1
        if int_len == 0:
            raise EEPKIError("All intermediate nodes are different")
        # Here paths of the proofs converge
        while int_len >= 1:
            if self.proof1.chain[-int_len][1] != self.proof2.chain[-int_len][1]:
                raise EEPKIError("Different direciton on the coverged paths")
            int_len -= 1
        return True

    def __str__(self):
        return "Proof1: %s\nProof2: %s" % (self.proof1, self.proof2)


class PolicyProof(BaseProof):
    """
    Complete proof of an SCP. It consists of either of n>0 presence proofs, or a
    single absence proof and N>=0 presence proofs. See... TODO(PSz)
    """
    TYPE = MsgFields.POLICY_PROOF
    def __init__(self, raw=None):
        self.proofs = []
        super().__init__(raw)

    def parse(self, raw):
        list_ = bin_to_obj(raw)
        if not len(list_):
            raise EEPKIParseError("Empty list")
        # TODO(PSz): This is pretty ugly, revise this encoding. Moving type to Proof helps
        tmp = list_[0]
        if MsgFields.ENTRY in bin_to_obj(tmp):
            self.proofs.append(PresenceProof(tmp))
        else:
            self.proofs.append(AbsenceProof(tmp))
        for tmp in list_[1:]:
            self.proofs.append(PresenceProof(tmp))

    def pack(self):
        list_ = []
        for proof in self.proofs:
            list_.append(proof.pack())
        return obj_to_bin(list_)

    @classmethod
    def from_values(cls, proofs):
        inst = cls()
        inst.proofs = proofs
        return inst

    def get_root(self):
        return self.proofs[-1].get_root()

    def validate(self, label, root, absence=False):
        if not self.proofs:
            raise EEPKIError("No proof")
        super().validate(label, root)
        # Check whether self.proofs has correct content
        if absence and not isinstance(self.proofs[0], AbsenceProof):
            raise EEPKIError("First proof's type incorrect")
        elif not absence and not isinstance(self.proofs[0], PresenceProof):
            raise EEPKIError("First proof's type incorrect")
        for proof in self.proofs[1:]:
            if not isinstance(proof, PresenceProof):
                raise EEPKIError("Non-first proof incorrect")
        # Validate proofs top-down
        tmp_root = root
        domains = get_domains(label)
        for idx, proof in enumerate(reversed(self.proofs)):
            proof.validate(domains[idx], tmp_root)
            if isinstance(proof, PresenceProof) and proof.entry.subtree:
                tmp_root = proof.entry.subtree.get_root()
            else:
                tmp_root = None
        # Final checks, first presence proof
        if not absence:
            if len(domains) != len(self.proofs):
                raise EEPKIError("Incorrect number of proofs")
            return True
        # Absence proof, first case where one domain doesn't have an SCP
        if isinstance(self.proofs[0], AbsenceProof):
            return True
        # An upper-domain doesn't have a subtree
        if len(domains) > len(self.proofs) and not self.proofs[0].entry.subtree:
            return True
        raise EEPKIError("Incorrect set of proofs")

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

    def parse(self, raw):
        list_ = bin_to_obj(raw)
        if len(list_) != 3:
            raise EEPKIParseError("len(list) == 3")
        if list_[0]:
            self.cons_proof = PresenceProof(list_[0])
        if list_[1]:
            self.policy_proof = PolicyProof(list_[1])
        tmp = list_[2]
        if MsgFields.ENTRY in bin_to_obj(tmp):
            self.cert_proof = PresenceProof(tmp)
        else:
            self.cert_proof = AbsenceProof(tmp)

    def pack(self):
        list_ = []
        for proof in [self.cons_proof, self.policy_proof, self.cert_proof]:
            if proof:
                list_.append(proof.pack())
            else:
                list_.append(None)
        return obj_to_bin(list_)

    @classmethod
    def from_values(cls, cons_proof, policy_proof, cert_proof=None):
        inst = cls()
        inst.cons_proof = cons_proof
        inst.policy_proof = policy_proof
        inst.cert_proof = cert_proof
        return inst

    def get_root(self):
        return self.cons_proof.get_root()

    def validate(self, scp_label, root, msc_label=None,
                 scp_absence=False, msc_absence=False):
        # TODO(PSz): should consider msc proofs only?
        if not self.cons_proof or not self.policy_proof:
            raise EEPKIError("No SCP/consistency proof")
        super().validate(scp_label, root)
        if (not isinstance(self.cons_proof, PresenceProof) or
            not isinstance(self.policy_proof, PolicyProof)):
            raise EEPKIError("Wrong type of SCP/consistency proof")
        # Few checks if msc is to be validated
        if msc_label:
            if not self.cert_proof:
                raise EEPKIError("No MSC proof")
            if msc_absence and not isinstance(self.cert_proof, AbsenceProof):
                raise EEPKIError("MSC proof is not AbsenceProof")
            if not msc_absence and not isinstance(self.cert_proof, PresenceProof):
                raise EEPKIError("MSC proof is not PresenceProof")
        # Check entry of consistency proof:
        if not isinstance(self.cons_proof.entry, RootsEntry):
            raise EEPKIError("Consistency proof not for RootsEntry")
        # Start the actual validation by checking consistency proof
        self.cons_proof.validate(None, root)
        for _, tmp in self.cons_proof.chain[1:-1]:
            if tmp != 'L':
                raise EEPKIError("Not the last RootsEntry")
        # Now check policy proof
        proot = self.cons_proof.entry.policy_tree_root
        croot = self.cons_proof.entry.cert_tree_root
        self.policy_proof.validate(scp_label, proot, scp_absence)
        if msc_label:
            self.cert_proof.validate(msc_label, croot)

    def get_cert_entry(self):
        if self.cert_proof:
            return self.cert_proof.entry
        return None

    def get_scp_entries(self):
        scps = []
        for proof in self.policy_proof:
            scps.append(proof.entry)
        return scps

    def __str__(self):
        res = ["EEPKIProof:"]
        res.append(str(self.cons_proof))
        res.append(str(self.policy_proof))
        res.append(str(self.cert_proof))
        return "\n".join(res)

def make_proof(raw):
    pass
