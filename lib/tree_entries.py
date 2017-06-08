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
from functools import total_ordering

from merkle import hash_function

from .cert import MSC, Revocation, SCP
from .defines import EEPKIParseError, MsgFields as MF
from .utils import bin_to_obj, obj_to_bin

@total_ordering
class TreeEntry(object):
    TYPE = "SHOULDN'T SEE THAT!!!"
    def __init__(self, raw):
        if raw:
            self.parse(raw)

    def parse(self, raw):
        dict_ = bin_to_obj(raw)
        if MF.TYPE not in dict_ or dict_[MF.TYPE] != self.TYPE:
            raise EEPKIParseError("No or incorrect type")
        return dict_

    def pack(self):  # Output is used for building an actual tree
        return {MF.TYPE: self.TYPE}

    def get_hash(self):
        return hash_function(self.pack()).digest()

    def get_label(self):  # Have to be implemented for entries of sorted trees
        raise NotImplementedError

    def __lt__(self, other):
        return self.get_label() < other.get_label()

    def __eq__(self, other):  # Used for sorting only
        return self.get_label() == other.get_label()

    def is_equal(self, other):
        return self.pack() == other.pack()

    def get_type(self):
        return self.TYPE


class RevocationEntry(TreeEntry):
    TYPE = MF.REV_ENTRY
    def __init__(self, raw=None):
        self.rev = None
        super().__init__(raw)

    def parse(self, raw):
        dict_ = super().parse(raw)
        if not MF.REV in dict_:
            raise EEPKIParseError("No REV entry")
        self.rev = Revocation(dict_[MF.REV])

    def pack(self):
        dict_ = super().pack()
        dict_[MF.REV] = self.rev.pack()
        return obj_to_bin(dict_)

    @classmethod
    def from_values(cls, rev):
        inst = cls()
        inst.rev = rev
        return inst


class MSCEntry(TreeEntry):
    TYPE = MF.MSC_ENTRY
    def __init__(self, raw=None):
        self.msc = None
        super().__init__(raw)

    def parse(self, raw):
        dict_ = super().parse(raw)
        if not MF.MSC in dict_:
            raise EEPKIParseError("No MSC entry")
        self.msc = MSC(dict_[MF.MSC])

    def pack(self):
        dict_ = super().pack()
        dict_[MF.MSC] = self.msc.pack()
        return obj_to_bin(dict_)

    @classmethod
    def from_values(cls, msc):
        inst = cls()
        inst.msc = msc
        return inst


class CertificateEntry(TreeEntry):
    """
    Representation of a MSC and its revocation (optional). These entries build
    the CertificateTree.
    """
    TYPE = MF.CERT_ENTRY
    def __init__(self, raw=None):
        self.msc = None
        self.rev = None
        super().__init__(raw)

    def parse(self, raw):
        dict_ = super().parse(raw)
        if not MF.MSC in dict_:
            raise EEPKIParseError("No MSC entry")
        self.msc = MSC(dict_[MF.MSC])
        if not MF.REV in dict_:
            raise EEPKIParseError("No REV entry")
        if dict_[MF.REV]:
            self.rev = Revocation(dict_[MF.REV])

    def pack(self):
        dict_ = super().pack()
        dict_[MF.MSC] = self.msc.pack()
        if self.rev:
            dict_[MF.REV] = self.rev.pack()
        else:
            dict_[MF.REV] = None
        return obj_to_bin(dict_)

    def get_label(self):
        return hash_function(self.msc.pem).digest()

    @classmethod
    def from_values(cls, msc, rev=None):
        inst = cls()
        inst.msc = msc
        inst.rev = rev
        return inst


class SCPEntry(TreeEntry):
    TYPE = MF.SCP_ENTRY
    def __init__(self, raw=None):
        self.scp = None
        super().__init__(raw)

    def parse(self, raw):
        dict_ = super().parse(raw)
        if not MF.SCP in dict_:
            raise EEPKIParseError("No SCP entry")
        self.scp = SCP(dict_[MF.SCP])

    def pack(self):
        dict_ = super().pack()
        dict_[MF.SCP] = self.scp.pack()
        return obj_to_bin(dict_)

    @classmethod
    def from_values(cls, scp):
        inst = cls()
        inst.scp = scp
        return inst

    def get_label(self):
        return self.scp.domain_name


class RootsEntry(TreeEntry):
    TYPE = MF.ROOTS_ENTRY
    def __init__(self, raw=None):
        self.policy_tree_root = None
        self.cert_tree_root = None
        super().__init__(raw)

    def parse(self, raw):
        dict_ = super().parse(raw)
        if not MF.POLICY_ROOT in dict_:
            raise EEPKIParseError("No POLICY_ROOT entry")
        self.policy_tree_root = dict_[MF.POLICY_ROOT]
        if not MF.CERT_ROOT in dict_:
            raise EEPKIParseError("No CERT_ROOT entry")
        self.cert_tree_root = dict_[MF.CERT_ROOT]

    def pack(self):
        dict_ = super().pack()
        dict_[MF.POLICY_ROOT] = self.policy_tree_root
        dict_[MF.CERT_ROOT] = self.cert_tree_root
        return obj_to_bin(dict_)

    @classmethod
    def from_values(cls, policy_tree_root, cert_tree_root):
        inst = cls()
        inst.policy_tree_root = policy_tree_root
        inst.cert_tree_root = cert_tree_root
        return inst

    def __str__(self):
        return "PolRoot: %s\nCertRoot: %s" % (self.policy_tree_root, self.cert_tree_root)


class PolicyEntry(TreeEntry):
    """
    Representation of an SCP and its subtree. These entries build the PolicyTree.
    """
    TYPE = MF.POLICY_ENTRY
    def __init__(self, raw=None):
        self.domain_name = None
        self.scp = None
        self.subtree = None
        self.subroot = None  # Only for parse()/pack() if subtree is None
        super().__init__(raw)

    def parse(self, raw):
        dict_ = super().parse(raw)
        if not MF.DNAME in dict_:
            raise EEPKIParseError("No DNAME entry")
        self.domain_name = dict_[MF.DNAME]
        if not MF.SCP in dict_:
            raise EEPKIParseError("No SCP entry")
        if dict_[MF.SCP]:
            self.scp = SCP(dict_[MF.SCP])
        if not MF.SUBROOT in dict_:
            raise EEPKIParseError("No SUBROOT entry")
        self.subroot = dict_[MF.SUBROOT]

    def pack(self):
        dict_ = super().pack()
        dict_[MF.DNAME] = self.domain_name
        if self.scp:
            dict_[MF.SCP] = self.scp.pack()
        else:
            dict_[MF.SCP] = None
        if self.subtree:
            dict_[MF.SUBROOT] = self.subtree.get_root()
        elif self.subroot:
            dict_[MF.SUBROOT] = self.subroot
        else:
            dict_[MF.SUBROOT] = None
        return obj_to_bin(dict_)

    @classmethod
    def from_values(cls, domain_name, scp=None, subtree=None):
        inst = cls()
        inst.domain_name = domain_name
        if scp:
            assert scp.domain_name == inst.domain_name
        inst.scp = scp
        inst.subtree = subtree
        return inst

    def get_label(self):
        return self.domain_name


def build_entry(raw):
    classes = [RevocationEntry, MSCEntry, CertificateEntry, SCPEntry, RootsEntry, PolicyEntry]
    dict_ = bin_to_obj(raw)
    if MF.TYPE not in dict_:
        raise EEPKIParseError("Type not found")
    type_ = dict_[MF.TYPE]
    for cls in classes:
        if cls.TYPE == type_:
            return cls(raw)
    raise EEPKIParseError("Class of type %s not found" % type_)
