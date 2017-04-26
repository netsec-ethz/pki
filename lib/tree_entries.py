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

# Stdlib
import json  # TODO(PSz): replace by a canonical parser

# External
from merkle import hash_function


class TreeEntry(object):
    TYPE = None
    def get_data(self):
        return {"type": self.TYPE}

    def get_label(self):  # Have to be implemented for entries of sorted trees
        raise NotImplementedError


class RevocationEntry(TreeEntry):
    TYPE = "rev"
    def __init__(self, msc):
        self.rev = rev
        super().__init__()

    def get_data(self):
        res = super().get_data()
        res['rev'] = self.rev.data  # TODO(PSz): check .data
        return json.dumps(res)


class MSCEntry(TreeEntry):
    TYPE = "msc"
    def __init__(self, msc):
        self.msc = msc
        super().__init__()

    def get_data(self):
        res = super().get_data()
        res['msc'] = self.msc.pem
        return json.dumps(res)


class CertificateEntry(TreeEntry):
    """
    Representation of a MSC and its revocation (optional). These entries build
    the CertificateTree.
    """
    TYPE = "msc_rev"
    def __init__(self, msc, rev=None):
        self.msc = msc
        self.rev = rev or None
        super().__init__()

    def get_data(self):
        res = super().get_data()
        res['msc'] = self.msc.pem
        res['rev'] = self.rev.data  # TODO(PSz): check .data
        return json.dumps(res)

    def get_label(self):
        return hash_function(self.msc.pem).digest()


class SCPEntry(TreeEntry):
    TYPE = "scp"
    def __init__(self, scp):
        self.scp = scp
        super().__init__()

    def get_data(self):
        res = super().get_data()
        res['scp'] = self.scp.pem
        return json.dumps(res)

    def get_label(self):
        return self.scp.domain_name


class RootsEntry(TreeEntry):
    TYPE = "roots"
    def __init__(self, policy_tree_root, cert_tree_root):
        self.policy_tree_root = policy_tree_root
        self.cert_tree_root = cert_tree_root

    def get_data(self):
        res = super().get_data()
        res['policy_root'] = self.policy_tree_root
        res['cert_root'] = self.cert_tree_root
        return json.dumps(res)
