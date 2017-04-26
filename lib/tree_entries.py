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
    def get_data_to_hash(self):
        # TODO(PSz): add some type encoding
        raise NotImplementedError

    def get_label(self):  # Have to be implemented for entries of sorted trees
        raise NotImplementedError


class RevocationEntry(TreeEntry):
    def __init__(msc):
        self.rev = rev
        super().__init__()

    def get_data_to_hash(self):
        return self.rev.data   # TODO(PSz): check .data


class MSCEntry(TreeEntry):
    def __init__(msc):
        self.msc = msc
        super().__init__()

    def get_data_to_hash(self):
        return self.msc.pem


class CertificateEntry(TreeEntry):
    """
    Representation of a MSC and its revocation (optional). These entries build
    the CertificateTree.
    """
    def __init__(msc, rev=None):
        self.msc = msc
        self.rev = rev or None
        super().__init__()

    def get_data_to_hash(self):
        res = {}
        res['msc'] = self.msc.pem
        res['rev'] = self.rev.data  # TODO(PSz): check .data
        return json.dumps(res)

    def get_label(self):
        return hash_function(self.msc.pem).digest()


class SCPEntry(TreeEntry):
    def __init__(scp):
        self.scp = scp
        super().__init__()

    def get_data_to_hash(self):
        return self.scp.pem

    def get_label(self):
        return self.scp.domain_name


class RootsEntry(TreeEntry):
    def __init__(policy_tree_root, cert_tree_root):
        self.policy_tree_root = policy_tree_root
        self.cert_tree_root = cert_tree_root

    def get_data_to_hash(self):
        return self.policy_tree_root + self.cert_tree_root
