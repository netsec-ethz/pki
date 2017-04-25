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

# External
from merkle import MerkleTree, Node

class TreeEntry(object):
    def __init__():
        self.added = None

    def get_data_to_hash(self):
        return b""

    def get_label(self):
        return None


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
            leaves.append(entry.get_data_to_hash())
        super().__init__(leaves)

    def add(self, entry):
        if self.sort:
            # find position and insert (entries + leaves)
            pass
        else:
            self.entries.append(entry)
            self.leaves.append(Node(entry.get_data_to_hash()))

    def add_hash(self, value):  # May be confusing, don't implement
        raise NotImplementedError
