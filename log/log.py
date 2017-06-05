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
        self.cons_tree = ConsistencyTree()
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
        se = SCPEntry(scp)
        self.ConsistencyTree.add(se)
        pe = PolicyEntry(scp.domain_name, scp)
        self.policy_tree(pe)

    def add_msc(self, msc):
        me = MSCEntry(msc)
        self.ConsistencyTree.add(me)
        ce = CertificateEntry(msc)
        self.cert_tree.update(me)

    def add_rev(self, rev):
        re = MSCEntry(rev)
        self.ConsistencyTree.add(re)
        msc = self.cons_tree.get_msc(rev.label)
        ce = CertificateEntry(msc, rev)
        self.cert_tree.update(me)

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
