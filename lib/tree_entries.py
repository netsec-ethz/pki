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
from .defines import EEPKIParseError, MsgFields
from .utils import bin_to_dict, dict_to_bin

@total_ordering
class TreeEntry(object):
    TYPE = "SHOULDN'T SEE THAT!!!"
    def __init__(self, raw):
        if raw:
            self.parse(raw)

    def parse(self, raw):
        raise NotImplementedError

    def pack(self):  # Output is used for building an actual tree
        raise NotImplementedError

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
    TYPE = MsgFields.REV_ENTRY
    def __init__(self, raw=None):
        self.rev = None
        super().__init__(raw)

    def pack(self):
        res = {}
        res[MsgFields.REV] = self.rev.pack()
        return dict_to_bin(res)

    @classmethod
    def from_values(cls, rev):
        inst = cls()
        inst.rev = rev
        return inst


class MSCEntry(TreeEntry):
    TYPE = MsgFields.MSC_ENTRY
    def __init__(self, raw=None):
        self.msc = None
        super().__init__(raw)

    def parse(self, raw):
        dict_ = bin_to_dict(raw)
        if not MsgFields.MSC in dict_:
            raise EEPKIParseError("No MSC entry")
        self.msc = MSC(dict_[MsgFields.MSC])

    def pack(self):
        res = {}
        res[MsgFields.MSC] = self.msc.pack()
        return dict_to_bin(res)

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
    TYPE = MsgFields.CERT_ENTRY
    def __init__(self, raw=None):
        self.msc = None
        self.rev = None
        super().__init__(raw)

    def parse(self, raw):
        dict_ = bin_to_dict(raw)
        if not MsgFields.MSC in dict_:
            raise EEPKIParseError("No MSC entry")
        self.msc = MSC(dict_[MsgFields.MSC])
        if not MsgFields.REV in dict_:
            raise EEPKIParseError("No REV entry")
        if dict_[MsgFields.REV]:
            self.rev = Revocation(dict_[MsgFields.REV])

    def pack(self):
        res = {}
        res[MsgFields.MSC] = self.msc.pack()
        if self.rev:
            res[MsgFields.REV] = self.rev.pack()
        else:
            res[MsgFields.REV] = None
        return dict_to_bin(res)

    def get_label(self):
        return hash_function(self.msc.pem).digest()

    @classmethod
    def from_values(cls, msc, rev=None):
        inst = cls()
        inst.msc = msc
        inst.rev = rev
        return inst


class SCPEntry(TreeEntry):
    TYPE = MsgFields.SCP_ENTRY
    def __init__(self, raw=None):
        self.scp = None
        super().__init__(raw)

    def parse(self, raw):
        dict_ = bin_to_dict(raw)
        if not MsgFields.SCP in dict_:
            raise EEPKIParseError("No SCP entry")
        self.scp = SCP(dict_[MsgFields.SCP])

    def pack(self):
        res = {}
        res[MsgFields.SCP] = self.scp.pack()
        return dict_to_bin(res)

    @classmethod
    def from_values(cls, scp):
        inst = cls()
        inst.scp = scp
        return inst

    def get_label(self):
        return self.scp.domain_name


class RootsEntry(TreeEntry):
    TYPE = MsgFields.ROOTS_ENTRY
    def __init__(self, raw=None):
        self.policy_tree_root = None
        self.cert_tree_root = None
        super().__init__(raw)

    def parse(self, raw):
        dict_ = bin_to_dict(raw)
        if not MsgFields.POLICY_ROOT in dict_:
            raise EEPKIParseError("No POLICY_ROOT entry")
        self.policy_tree_root = dict_[MsgFields.POLICY_ROOT]
        if not MsgFields.CERT_ROOT in dict_:
            raise EEPKIParseError("No CERT_ROOT entry")
        self.cert_tree_root = dict_[MsgFields.CERT_ROOT]

    def pack(self):
        res = {}
        res[MsgFields.POLICY_ROOT] = self.policy_tree_root
        res[MsgFields.CERT_ROOT] = self.cert_tree_root
        return dict_to_bin(res)

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
    TYPE = MsgFields.POLICY_ENTRY
    def __init__(self, raw=None):
        self.domain_name = None
        self.scp = None
        self.subtree = None
        self.subroot = None  # Only for parse()/pack() if subtree is None
        super().__init__(raw)

    def parse(self, raw):
        dict_ = bin_to_dict(raw)
        if not MsgFields.DNAME in dict_:
            raise EEPKIParseError("No DNAME entry")
        self.domain_name = dict_[MsgFields.POLICY_ROOT]
        if not MsgFields.SCP in dict_:
            raise EEPKIParseError("No SCP entry")
        if dict_[MsgFields.SCP]:
            self.scp = SCP(dict_[MsgFields.SCP])
        if not MsgFields.SUBROOT in dict_:
            raise EEPKIParseError("No SUBROOT entry")
        self.subroot = dict_[MsgFields.SUBROOT]

    def pack(self):
        res = {}
        res[MsgFields.DNAME] = self.domain_name
        if self.scp:
            res[MsgFields.SCP] = self.scp.pack()
        else:
            res[MsgFields.SCP] = None
        if self.subtree:
            res[MsgFields.SUBROOT] = self.subtree.get_root()
        elif self.subroot:
            res[MsgFields.SUBROOT] = self.subroot
        else:
            res[MsgFields.SUBROOT] = None
        return dict_to_bin(res)

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
