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

from .utils import dict_to_cbor
from .defines import MsgFields

@total_ordering
class TreeEntry(object):
    TYPE = None
    def __init__(self, raw):
        if raw:
            self.parse(raw)

    def parse(self, raw):
        raise NotImplementedError

    def pack(self):  # Output is used for building an actual tree
        return {MsgFields.TYPE: self.TYPE}

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


# PSz: consider id as get_label() for entries of ConsistencyTree
class RevocationEntry(TreeEntry):
    TYPE = MsgFields.REV
    def __init__(self, raw=None):
        self.rev = None
        super().__init__(raw)

    def pack(self):
        res = super().pack()
        res[MsgFields.REV] = self.rev.pack()
        return dict_to_cbor(res)

    @classmethod
    def from_values(cls, rev):
        inst = cls()
        inst.rev = rev
        return inst


class MSCEntry(TreeEntry):
    TYPE = MsgFields.MSC
    def __init__(self, raw=None):
        self.msc = None
        super().__init__(raw)

    def pack(self):
        res = super().pack()
        res[MsgFields.MSC] = self.msc.pack()
        return dict_to_cbor(res)

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
    TYPE = MsgFields.CERT
    def __init__(self, raw=None):
        self.msc = None
        self.rev = None
        super().__init__(raw)

    def pack(self):
        res = super().pack()
        res[MsgFields.MSC] = self.msc.pack()
        if self.rev:
            res[MsgFields.REV] = self.rev.pack()
        else:
            res[MsgFields.REV] = None
        return dict_to_cbor(res)

    def get_label(self):
        return hash_function(self.msc.pem).digest()

    @classmethod
    def from_values(cls, msc, rev=None):
        inst = cls()
        inst.msc = msc
        inst.rev = rev
        return inst


class SCPEntry(TreeEntry):
    TYPE = MsgFields.SCP
    def __init__(self, raw=None):
        self.scp = None
        super().__init__(raw)

    def pack(self):
        res = super().pack()
        res[MsgFields.SCP] = self.scp.pack()
        return dict_to_cbor(res)

    @classmethod
    def from_values(cls, scp):
        inst = cls()
        inst.scp = scp
        return inst

    def get_label(self):
        return self.scp.domain_name


class RootsEntry(TreeEntry):
    TYPE = MsgFields.ROOTS
    def __init__(self, raw=None):
        self.policy_tree_root = None
        self.cert_tree_root = None
        super().__init__(raw)

    def pack(self):
        res = super().pack()
        res[MsgFields.POLICY_ROOT] = self.policy_tree_root
        res[MsgFields.CERT_ROOT] = self.cert_tree_root
        return dict_to_cbor(res)

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
    TYPE = MsgFields.POLICY
    def __init__(self, raw=None):
        self.domain_name = None
        self.scp = None
        self.subtree = None
        super().__init__(raw)

    def pack(self):
        res = super().pack()
        if self.scp:
            res[MsgFields.SCP] = self.scp.pack()
        else:
            res[MsgFields.SCP] = None
        if self.subtree:
            res[MsgFields.SUBROOT] = self.subtree.get_root()
        else:
            res[MsgFields.SUBROOT] = None
        return dict_to_cbor(res)

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
