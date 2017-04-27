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
from base64 import b64decode, b64encode

from merkle import join_chains  # TODO(PSz): rather re-implement

from .utils import dict_to_json


class BaseProof(object):
    TYPE = None
    def __init__(self, raw):
        self.raw = raw
        self.extra_entries = []
        self.parse(raw)

    def parse(self, raw):
        raise NotImplementedError

    def pack(self):
        return {"type": self.TYPE}

    @classmethod
    def from_values(cls):
        raise NotImplementedError

    def verify(self, external_root=None):
        raise NotImplementedError

    def join(self, higher_proof):
        """
        Extend (if possible) the self proof by the higher_proof.
        """
        raise NotImplementedError


class PresenceProof(ProofBase):
    TYPE = "presence"
    def __init__(self, raw):
        self.entry = None
        self.chain = None
        super().__init__(raw)

    def pack(self):
        tmp = super().__pack__()
        # TODO(PSz): other fields + base64
        return dict_to_json(tmp)


class AbsenceProof(ProofBase):
    """
    TODO(PSz): describe how it is encoded
    """
    TYPE = "absence"
    def __init__(self, raw):
        self.entry1 = None
        self.chain1 = None
        self.entry2 = None
        self.chain2 = None
        super().__init__(raw)

    def pack(self):
        tmp = super().__pack__()
        # TODO(PSz): other fields + base64
        return dict_to_json(tmp)
