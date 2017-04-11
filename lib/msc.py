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

from cryptography.x509 import CertificatePolicies, ExtensionNotFound

from lib.defines import SecLevel
from lib.x509 import binding_from_pem, certs_to_pem, get_cn, pem_to_certs, verify_cert_chain


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


class MSC(object):
    """
    Multi-signature certificate.
    """
    def __init__(self, pem):
        self.pem = pem
        self.domain_name = ""
        self.chains = []
        self.policy_binding = []
        self._parse(pem)
        assert self._verify_msc_integrity()  # TODO(PSz): raise an exception

    def _parse(self, pem):
        certs = pem_to_certs(pem)
        if not certs:
            return
        # TODO(PSz): Check domain_name everywhere
        self.domain_name = get_cn(certs[0])
        self.policy_binding = certs[-1]  # The last cert is a policy binding
        # Parse certificate chains
        chain = []
        for cert in reversed(certs[:-1]):
            chain.insert(0, cert)
            # End of the chain
            if get_cn(cert) == self.domain_name:
                self.chains.insert(0, chain)
                chain = []
        assert not chain  # TODO(PSz): unterminated chain, raise an exception

    def __str__(self):
        tmp = ["MSC\n"]
        tmp.append("Domain: %s\n" % self.domain_name)
        for chain in self.chains:
            tmp.append("Chain: %s\n" % chain)
        tmp.append("Policy Binding: %s\n" % self.policy_binding)
        return "".join(tmp)

    def _verify_policy_binding_auth(self):
        return True

    def _verify_msc_integrity(self):
        print("_verify_msc_integrity")
        sep = b'-----BEGIN CERTIFICATE-----\n'
        # Skip the policy binding (the last element)
        pem = sep.join(self.pem.split(sep)[:-1])
        # Generate policy binding from the pem
        pi, _ = binding_from_pem(pem)
        # Compare with the MSC's policy binding
        try:
            exts = self.policy_binding.extensions.get_extension_for_class(CertificatePolicies)
            return pi == exts.value
        except ExtensionNotFound:
            logging.error("Certificate binding not found.")
            return False

    def _verify_against_trc(self, trc):
        return True

    def _verify_against_scp(self, scp):
        return True

    def verify_chains(self, trusted_certs):
        print("verify_chains")
        res = []
        for chain in self.chains:
            pem = certs_to_pem(chain)
            if verify_cert_chain(pem, trusted_certs):
                res.append(VrfyResults(chain))
        return res
