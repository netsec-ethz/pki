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
import bisect
import logging

# External
from merkle import MerkleTree, Node


class BaseTree(MerkleTree):
    def __init__(entries=None, sort=False):
        self.entries = []
        if entries is not None:
            self.entries = entries
        self.sort = sort
        if self.sort:
            self.entries.sort()
        # Build an actual tree
        leaves = []
        for entry in entries:
            leaves.append(entry.get_data())
        super().__init__(leaves)

    def add(self, entry):
        if self.sort:  # Leaves of the tree are sorted
            index = bisect.bisect_left(self.entries, entry)
            if self.entries and self.entries[index] == entry:
                logging.info("Replacing entry: %s by %s" % (self.entries[index], entry))
                self.entries[index] = entry
                self.leaves[index] = Node(entry.get_data())
            else:
                self.entries.insert(index, entry)
                self.leaves.insert(index, Node(entry.get_data()))
        else:  # Append-only tree
            self.entries.append(entry)
            self.leaves.append(Node(entry.get_data()))

    def add_hash(self, value):  # Not needed and may be confusing, don't implement
        raise NotImplementedError

    def add_adjust(self, data, prehashed=False):  # Ditto
        raise NotImplementedError
