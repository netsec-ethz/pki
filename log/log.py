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
import logging

from pki.lib.cert import MSC, Revocation, SCP
from pki.lib.trees import  CertificateTree, ConsistencyTree, PolicyTree
from pki.lib.tree_entries import (
    CertificateEntry,
    MSCEntry,
    RevocationEntry,
    RootsEntry,
    SCPEntry,
    PolicyEntry,
    )
from pki.lib.tree_proofs import EEPKIProof


class Log(object):
    """
    Log class used by servers (actual logs) and auditors
    """
    def __init__(self, entries=[]): #, trc, log_id, db_path, key_path=None):
        self.cons_tree = ConsistencyTree()
        self.policy_tree = PolicyTree()
        self.cert_tree = CertificateTree()
        for entry in entries:
            self.add(entry)
        self.build(add_re=False)  # Don't add RootsEntry when pre-loaded

    def build(self, add_re=True):
        self.policy_tree.build()
        self.cert_tree.build()
        if add_re:
            re = RootsEntry.from_values(self.policy_tree.get_root(), self.cert_tree.get_root())
            self.cons_tree.add(re)
        self.cons_tree.build()

    def add_entry(self, entry):
        obj = None
        if isinstance(entry, MSCEntry):
            obj = entry.msc
        elif isinstance(entry, SCPEntry):
            obj = entry.scp
        elif isinstance(entry, RevocationEntry):
            obj = entry.rev
        elif isinstance(entry, RootsEntry):
            obj = entry
        else:
            raise EEPKIError("Invalid entry to add: %s" % entry)
        self.add(obj)

    def add(self, obj):
        if isinstance(obj, MSC):
            self.add_msc(obj)
        elif isinstance(obj, SCP):
            self.add_scp(obj)
        elif isinstance(obj, Revocation):
            self.add_rev(obj)
        elif isinstance(obj, RootsEntry):
            self.cons_tree.add(obj)
        else:
            raise EEPKIError("Cannot add %s" % obj)

    def add_scp(self, scp):
        se = SCPEntry.from_values(scp)
        self.cons_tree.add(se)
        pe = PolicyEntry.from_values(scp.domain_name, scp)
        self.policy_tree.add(pe)

    def add_msc(self, msc):
        me = MSCEntry.from_values(msc)
        self.cons_tree.add(me)
        ce = CertificateEntry.from_values(msc)
        self.cert_tree.add(ce)

    def add_rev(self, rev):
        re = RevocationEntry.from_values(rev)
        self.cons_tree.add(re)
        ce = self.cert_tree.get_entry(rev.label)
        if not ce.rev:
            logging.warning("Adding revocation for %s" % rev.label)
            ce.rev = rev

    def get_root_entries(self):
        return self.cons_tree.get_root(), len(self.cons_tree.entries)

    def sign_root(self):
        raise NotImplementedError

    def get_signed_root(self):
        raise NotImplementedError

    def get_proof(self, scp_label, msc_label=None):
        policy_proof = self.policy_tree.get_proof(scp_label)
        cert_proof = None
        if msc_label:
            cert_proof = self.cert_tree.get_proof(msc_label)
        # RootsEntry is always the last entry of the ConsistencyTree
        last_idx = len(self.cons_tree.entries) - 1
        cons_proof = self.cons_tree.get_proof_idx(last_idx)
        return EEPKIProof.from_values(cons_proof, policy_proof, cert_proof)
