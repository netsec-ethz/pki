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
from pki.lib.trees import  CertificateTree, ConsistencyTree, PolicyTree
from pki.lib.tree_entries import RevocationEntry, MSCEntry, SCPEntry, 
from pki.lib.tree_proofs import EEPKIProof


class Log(object):
    def __init__(self):
        self.cons_tree = CertificateTree()
        self.policy_tree = PolicyTree()
        self.cert_tree = CertificateTree()

        self.update()

    def update(self):
        self.policy_tree.update()
        self.cert_tree.update()
        re = RootsEntry(self.policy_tree.get_root(), self.cons_tree.update())
        self.cons_tree.add(re)
        self.cons_tree.update()

    def add_scp(self, scp):
        # check version etc...
        pass

    def add_msc(self, scp):
        pass

    def add_rev(self, scp):
        pass

    def get_root(self):
        return self.cons_tree.get_root()

    def get_proof(scp_label, msc_label=None):
        policy_proof = self.policy_tree.get_proof(scp_label)
        cert_proof = None
        if msc_label:
            cert_proof = self.cert_tree.get_proof(msc_label)
        # RootsEntry is always the last entry of the ConsistencyTree
        last_idx = len(self.cons_tree.entries) - 1
        cons_proof = self.cons_tree.get_proof_idx(last_idx)
        return EEPKIProof.from_values(cons_proof, policy_proof, cert_proof)
