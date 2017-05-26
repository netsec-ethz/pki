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

    def get_proof_idx(self, idx):
        if 0 <= idx < len(self.leaves):
            return self.get_chain(idx)
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
        idx = self.get_idx_for_label(label)
        entries_no = len(self.entries)
        if entries_no and idx < entries_no and label == self.entries[idx].get_label():
            self._handle_existing_entry(idx, entry)
        else:
            self.entries.insert(idx, entry)
            self.leaves.insert(idx, Node(entry.get_data()))

    def _handle_existing_entry(self, idx, entry):
        raise NotImplementedError

    def get_idx_for_label(self, label):
        keys = [e.get_label() for e in self.entries]
        return bisect.bisect_left(keys, label)

    def get_entry(self, label):
        idx = self.get_idx_for_label(label)
        entries_no = len(self.entries)
        if entries_no and idx < entries_no and label == self.entries[idx].get_label():
            return self.entries[idx]
        return None

    def get_proof(self, entry):
        if not self.entries:
            return None
        idx = get_idx_for_label(entry)
        if self.entries[idx] == entry:
            return self.get_proof_idx(idx)
        else:
            return self.get_absence_proof_idx(idx-1, idx)

    def get_absence_proof_idx(self, idx1, idx2):
        # TODO(PSz): entries should be returned as well
        proof1 = get_proof_idx(idx1)
        proof2 = get_proof_idx(idx2)
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

    def _handle_existing_entry(self, idx, entry):
        logging.error("Entry with the label exists: %s" % entry.get_label())

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

    def _handle_existing_entry(self, idx, entry):
        logging.info("updating policy entry: %s by %s" % (self.entries[idx], entry))
        # PSz: Check version here?(rather when accepting the entry)
        self.entries[idx].scp = entry.scp
        self.leaves[idx] = Node(self.entries[idx].get_data())

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
        domain_name = scp.domain_name
        if not domain_name:
            logging.error("Trying to add policy for dn: %s" % domain_name)
            return
        tree = self.tld_tree
        entry = None
        # Go to the last subtree, creating intermediate ones (if necessary)
        for name in get_domains(domain_name)[:-1]:
            entry = tree.get_entry(name)
            if not entry:
                print("Creating entry for %s" % name)
                entry = PolicyEntry(name)
                tree.add(entry)
            tree = entry.subtree
            if not tree:
                print("Creating subtree for %s" % name)
                tree = PolicySubTree()
                if entry:
                    print("Created subtree assigned to entry: %s" % entry.get_label())
                    entry.subtree = tree
        # Now add entry with SCP (it updates it if existing)
        tree.add(scp)

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
