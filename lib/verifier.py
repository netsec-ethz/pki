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

from pki.lib.defines import FailCase, SecLevel
from pki.lib.x509 import get_cn, cert_from_der, certs_to_pem


class VrfyResults(object):
    """
    Helper class for storing results of a successful chain verification.
    """
    def __init__(self, chain):
        self.ca = get_cn(chain[-1])
        self.path_len = len(chain)
        # TODO(PSz): derive the following
        self.sec_lvl = SecLevel.MEDIUM
        self.ev = False
        self.valid_for = 12345
        self.wildcard = False

    def __repr__(self):
        s = "<VrfyResult: "
        s += "CA: %s, PathLen: %d, SecLvl: %s, EV: %s, ValidFor: %d, Wildcard: %s" %  (self.ca,
            self.path_len, self.sec_lvl, self.ev, self.valid_for, self.wildcard)
        s += ">"
        return s


class Verifier(object):
    """
    MSC and SCP verifier.
    """

    def __init__(self, domain_name, msc, scps, proof, trc):
        self.domain_name = domain_name
        self.msc = msc
        self.scps = scps
        self.proof = proof
        self.trc = trc

    def _get_trusted(self, use_policy=False):
        """
        Returns list of trusted certificates (PEM) from TRC.
        List is filtered by policy if use_policy is True.
        """
        trusted = []
        for ca, der in self.trc.root_cas.items():
            if use_policy:
                if ca not in self.scp.policy['CA_LIST']:
                    logging.warning("%s not in %s" % (ca, self.scp.policy['CA_LIST']))
                    continue
            # Convert DER to PEM
            trusted.append(certs_to_pem([cert_from_der(der)]))
        return trusted

    def _get_scps_cas(self):
        res = set()
        for scp in self.scps:
            if 'CA_LIST' in scp.policy:
                res.update(scp.policy['CA_LIST'])
        return update

    def verify(self):
        """
        Returns either (True, None) or (False, FailCase.SOFT) or (False, FailCase.HARD)
        """
        # First verify proofs
        if not self._verify_proof():
            return (False, FailCase.HARD)
        if not self._verify_scps():
            return (False, FailCase.HARD)
        return self._verify_msc()


        # return (False, FailCase.SOFT)
        # return (False, FailCase.HARD)
        return (True, None)

    def _verify_proof(self):
        """
        Verify whether the proof is fresh and matches the MSC and SCP.
        """
        return True

    def _verify_scps(self):
        """
        Verify whether SCPs matches the TRC (trusted CAs and threshold number).
        """
        trusted = self._get_trusted()
        for scp in self.scps:
            # Verify certificate chains in SCP
            res = scp.verify_chains(trusted)
            # Check whether successful results are >= threshold
            print(res)
            if len(res) < self.trc.quorum_eepki:
                logging.error("quroum_eepki not satisfied: %d < %d for %s" %
                              (len(res), self.trc.quorum_eepki, scp))
                return False
        return True

    def _verify_msc(self):
        """
        Verify whether MSC matches the SCP and domain name.
        """
        # First check whether domain name matches
        if self.domain_name != self.msc.domain_name:
            logging.error("%s != %s" % (self.domain_name, self.msc.domain_name))
            return (False, FailCase.HARD)

        # Verify MSC's chains based on the SCP's trusted CAs
        trusted = self._get_trusted(True)
        res = self.msc.verify_chains(trusted)
        print(res)
        params = self._determine_policy()
        # TODO(PSz): here start validating res according to the policy
        # return (False, FailCase.SOFT)
        # return (False, FailCase.HARD)
        return (True, None)

    def _determine_policy(self):
        # Determine final policy parameters, based on SCPs
        return None
