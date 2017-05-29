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
    def get_data(self):
        return {MsgFields.TYPE: self.TYPE}

    def get_hash(self):
        return hash_function(self.get_data()).digest()

    def get_label(self):  # Have to be implemented for entries of sorted trees
        raise NotImplementedError

    def __lt__(self, other):
        return self.get_label() < other.get_label()

    def __eq__(self, other):  # FIXME(PSz): That may be misleading, get_data()?
        return self.get_label() == other.get_label()


# PSz: consider id as get_label() for entries of ConsistencyTree
class RevocationEntry(TreeEntry):
    TYPE = MsgFields.REV
    def __init__(self, rev):
        self.rev = rev
        super().__init__()

    def get_data(self):
        res = super().get_data()
        res[MsgFields.REV] = self.rev.raw
        return dict_to_cbor(res)


class MSCEntry(TreeEntry):
    TYPE = MsgFields.MSC
    def __init__(self, msc):
        self.msc = msc
        super().__init__()

    def get_data(self):
        res = super().get_data()
        res[MsgFields.MSC] = self.msc.pem
        return dict_to_cbor(res)


class CertificateEntry(TreeEntry):
    """
    Representation of a MSC and its revocation (optional). These entries build
    the CertificateTree.
    """
    TYPE = MsgFields.CERT
    def __init__(self, msc, rev=None):
        self.msc = msc
        self.rev = rev or None
        super().__init__()

    def get_data(self):
        res = super().get_data()
        res[MsgFields.MSC] = self.msc.pem
        if self.rev:
            res[MsgFields.REV] = self.rev.raw
        else:
            res[MsgFields.REV] = None
        return dict_to_cbor(res)

    def get_label(self):
        return hash_function(self.msc.pem).digest()


class SCPEntry(TreeEntry):
    TYPE = MsgFields.SCP
    def __init__(self, scp):
        self.scp = scp
        super().__init__()

    def get_data(self):
        res = super().get_data()
        res[MsgFields.SCP] = self.scp.pem
        return dict_to_cbor(res)

    def get_label(self):
        return self.scp.domain_name


class RootsEntry(TreeEntry):
    TYPE = MsgFields.ROOTS
    def __init__(self, policy_tree_root, cert_tree_root):
        self.policy_tree_root = policy_tree_root
        self.cert_tree_root = cert_tree_root

    def get_data(self):
        res = super().get_data()
        res[MsgFields.POLICY_ROOT] = self.policy_tree_root
        res[MsgFields.CERT_ROOT] = self.cert_tree_root
        return dict_to_cbor(res)


class PolicyEntry(TreeEntry):
    """
    Representation of an SCP and its subtree. These entries build the PolicyTree.
    """
    TYPE = MsgFields.POLICY
    def __init__(self, domain_name, scp=None, subtree=None):
        self.domain_name = domain_name
        if scp:
            assert scp.domain_name == self.domain_name
        self.scp = scp
        self.subtree = subtree
        super().__init__()

    def get_data(self):
        res = super().get_data()
        if self.scp:
            res[MsgFields.SCP] = self.scp.pem
        else:
            res[MsgFields.SCP] = None
        if self.subtree:
            res[MsgFields.SUBROOT] = self.subtree.root
        else:
            res[MsgFields.SUBROOT] = None
        return dict_to_cbor(res)

    def get_label(self):
        return self.domain_name
