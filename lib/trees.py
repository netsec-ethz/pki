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
import bisect
import logging

from merkle import MerkleTree, Node, hash_function

from .tree_entries import (
    CertificateEntry,
    MSCEntry,
    RevocationEntry,
    RootsEntry,
    SCPEntry,
    )


class BaseTree(MerkleTree):
    def __init__(self, entries=None):
        self.entries = []
        if entries is not None:
            self.entries = entries
        # Build an actual tree
        leaves = []
        for entry in entries:
            leaves.append(entry.get_data())
        super().__init__(leaves)

    def get_root(self):
        if self.root:
            return self.root.val
        return hash_function(b"").digest()

    def get_proof(self, index):
        if 0 <= index < len(self.leaves):
            return self.get_chain(index)
        return None

    def add_hash(self, value):  # Not needed and may be confusing, don't implement
        raise NotImplementedError

    def add_adjust(self, data, prehashed=False):  # Ditto
        raise NotImplementedError


class ApendOnlyTree(BaseTree):
    def add(self, entry):
        self.entries.append(entry)
        self.leaves.append(Node(entry.get_data()))


class SortedTree(BaseTree):
    def __init__(self, entries=None):
        tmp = []
        if entries:
            tmp = sorted(entries)
        super().__init__(tmp)

    def add(self, entry):
        index = self.get_idx_for_entry(entry)
        if self.entries and self.entries[index] == entry:
            logging.info("Replacing entry: %s by %s" % (self.entries[index], entry))
            self.entries[index] = entry
            self.leaves[index] = Node(entry.get_data())
        else:
            self.entries.insert(index, entry)
            self.leaves.insert(index, Node(entry.get_data()))

    def get_idx_for_entry(self, entry):
        bisect.bisect_left(self.entries, entry)

    def get_idx_for_hash(self, hash_):
        bisect.bisect_left(self.leaves, hash_)

    def get_proof(self, entry):
        presence = self.get_presence_proof(entry)
        if presence:
            return presence
        return self.get_absence_proof(entry)

    def get_presence_proof(self, entry):
        raise NotImplementedError

    def get_absence_proof(self, entry):  # Can be implemented only by sorted trees
        raise NotImplementedError


class ConsistencyTree(AppendOnlyTree):
    """
    Tree that contains all object in chronological order. See Section 5.3 and
    Figure 5 from the PoliCert paper.
    """
    def get_presence_proof(self, entry):
        raise NotImplementedError


class CertificateTree(SortedTree):
    """
    Tree that contains all certificates and their (optional) revocations.
    Entries of the tree are sorted. See Section 5.3 and Figure 3 from the
    PoliCert paper.
    """
    def __init__(self, entries=None):
        # Consider a list of accepted requests
        super().__init__(entries, True)  # Sorted tree

    def get_entry_by_hash(self, hash_):
        raise NotImplementedError

    def add_revocation(self, rev):
        raise NotImplementedError


class PolicySubTree(SortedTree):
    """
    Tree that contains all policies for a given domain level (e.g., all policies
    of X.a.com, or all TLD policies). Entries of the tree are sorted. See
    Section 5.3 and Figure 4 from the PoliCert paper.
    """
    def __init__(self, domain_name, entries=None):
        super().__init__(entries, True)  # Sorted tree
        self.domain_name = domain_name
        self.subtree = None  # Pointer to a child tree

    def get_subtree_root(self):
        raise NotImplementedError


class PolicyTree(object):
    """
    Forest that contains all trees (with policies) for all domains. Entries of
    the trees are sorted. See Section 5.3 and Figure 4 from the PoliCert paper.
    """
    def __init__(self, entries=None):
        self.tld_tree = PolicySubTree(b"")
        if entries:
            self.create_trees(entries)

    def create_trees(entries):
        raise NotImplementedError

    def get_entry_by_name(self, name):
        raise NotImplementedError

    def add_revocation(self, rev):
        raise NotImplementedError
