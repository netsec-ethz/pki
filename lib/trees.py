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
    PolicyEntry,
    RevocationEntry,
    RootsEntry,
    SCPEntry,
    )
from .utils import get_domains


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
        self.needs_rebuild = True

    def build(self):
        super().build()
        self.needs_rebuild = False

    def get_root(self):
        if self.root:
            return self.root.val
        return None

    def get_proof_idx(self, index):
        if 0 <= index < len(self.leaves):
            return self.get_chain(index)
        return None

    def add_hash(self, value):  # Not needed and may be confusing, don't implement
        raise NotImplementedError

    def add_adjust(self, data, prehashed=False):  # Ditto
        raise NotImplementedError

    def __str__(self):
        return self.__class__.__name__ + ": "

    def __repr__(self):
        return self.__str__()


class ConsistencyTree(BaseTree):
    """
    Tree that contains all object in chronological order. See Section 5.3 and
    Figure 5 from the PoliCert paper.
    """
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
        label = entry.get_label()
        index = self.get_idx_for_label(label)
        if self.entries and label == self.entries[index].get_label():
            self._handle_existing_entry(index, entry)
        else:
            self.entries.insert(index, entry)
            self.leaves.insert(index, Node(entry.get_data()))

    def _handle_existing_entry(self, index, entry):
        logging.info("Replacing entry: %s by %s" % (self.entries[index], entry))
        # self.entries[index] = entry
        # self.leaves[index] = Node(entry.get_data())

    def get_idx_for_label(self, label):
        keys = [e.get_label() for e in self.entries]
        return bisect.bisect_left(keys, label)

    def get_entry(self, label):
        idx = self.get_idx_for_label(label)
        if label == self.entries[idx].get_label():
            return self.entries[idx]
        return None

    def get_idx_for_hash(self, hash_):
        return bisect.bisect_left(self.leaves, hash_)

    def get_proof(self, entry):
        if not self.entries:
            return None
        index = get_idx_for_label(entry)
        if self.entries[index] == entry:
            return self.get_proof_idx(index)
        else:
            return self.get_absence_proof_idx(index-1, index)

    def get_absence_proof_idx(self, index1, index2):
        # TODO(PSz): entries should be returned as well
        proof1 = get_proof_idx(index1)
        proof2 = get_proof_idx(index2)
        return (proof1, proof2)


class CertificateTree(SortedTree):
    """
    Tree that contains all certificates and their (optional) revocations.
    Entries of the tree are sorted. See Section 5.3 and Figure 3 from the
    PoliCert paper.
    """
    def __init__(self, entries=None):
        # PSz: Consider a list of accepted requests
        super().__init__(entries)  # Sorted tree

    def add_revocation(self, rev):
        raise NotImplementedError

    def __str__(self):
        l = []
        for e in self.entries:
            l.append(e.get_label().hex()[:10]+"...")
        return super().__str__() + "  ".join(l)

class PolicySubTree(SortedTree):
    """
    Tree that contains all policies for a given domain level (e.g., all policies
    of X.a.com, or all TLD policies). Entries of the tree are sorted. See
    Section 5.3 and Figure 4 from the PoliCert paper.
    """
    def __init__(self, entries=None):
        super().__init__(entries)  # Sorted tree

    def _handle_existing_entry(self, index, entry):
        logging.info("updating policy entry: %s by %s" % (self.entries[index], entry))
        # PSz: Check version here?(rather when accepting the entry)
        self.entries[index].scp = entry.scp
        self.leaves[index] = Node(self.entries[index].get_data())

    def __str__(self):
        l = []
        for e in self.entries:
            l.append(e.get_label())
        return super().__str__() + "  ".join(l)

class PolicyTree(object):
    """
    Forest that contains all trees (with policies) for all domains. Entries of
    the trees are sorted. See Section 5.3 and Figure 4 from the PoliCert paper.
    """
    def __init__(self, entries=None):
        self.tld_tree = PolicySubTree()
        for e in entries or []:
            self.add(e)

    def add(self, scp):
        if not scp.domain_name:
            logging.error("Trying to add policy for dn: %s" % scp.domain_name)
            return
        tree = self.tld_tree
        entry = None
        # Go to the last subtree, creating intermediate ones (if necessary)
        for name in get_domains(scp.domain_name)[-1]:
            if not tree:
                print()
                tree = PolicySubTree()
                if entry:
                    entry.subtree = tree
            entry = tree.get_entry(name)
            if not entry:
                entry = PolicyEntry(name)
                tree.add(entry)
            tree = entry.subtree
        # Now add entry with SCP
        entry = PolicyEntry(name, scp)
        tree.add(entry)

    def get_entry(self, label):
        tree = self.tld_tree
        entry = None
        for name in get_domains(label):
            if not tree:
                return None
            entry = tree.get_entry(name)
            if not entry:
                return None
        return entry

    def add_revocation(self, rev):
        raise NotImplementedError

    def get_root(self):
        return self.tld_tree.get_root()

    def build(self):
        raise NotImplementedError  # rebuild all trees
