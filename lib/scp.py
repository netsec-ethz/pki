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

from cryptography.x509 import CertificatePolicies

from lib.defines import CERT_SEP, SecLevel
from lib.x509 import (binding_from_pem, certs_to_pem, get_cn, pem_to_certs,
        policy_from_cert, verify_cert_chain)


class SCP(object):
    """
    Subject certificate policy.
    """
    def __init__(self, pem):
        self.pem = pem
        self.domain_name = ""
        self.chains = []
        self.policy = b""
        self._parse(pem)

    def _parse(self, pem):
        certs = pem_to_certs(pem)
        if not certs:
            return
        self.domain_name = get_cn(certs[0])
        # Get policy
        self.policy = policy_from_cert(certs[0])
        assert self.policy
        # Parse certificate chains
        chain = []
        for cert in reversed(certs):
            chain.insert(0, cert)
            # End of the chain
            if get_cn(cert) == self.domain_name:
                assert self.policy == policy_from_cert(cert)  # TODO(PSz): exception
                self.chains.insert(0, chain)
                chain = []
        assert not chain  # TODO(PSz): unterminated chain, raise an exception

    def verify_chains(self, trusted_certs):
        print("verify_chains")
        res = []
        for chain in self.chains:
            pem = certs_to_pem(chain)
            if verify_cert_chain(pem, trusted_certs):
                res.append(VrfyResults(chain))
        return res  # CAs might be non-unique

    def __repr__(self):
        tmp = ["SCP\n"]
        tmp.append("Domain: %s\n" % self.domain_name)
        for chain in self.chains:
            tmp.append("Chain: %s\n" % chain)
        tmp.append("Policy: %s\n" % self.policy)
        return "".join(tmp)

