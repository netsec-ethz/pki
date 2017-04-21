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

from pki.lib.defines import CERT_SEP, SecLevel
from pki.lib.x509 import (
        ChainProperties,
        binding_from_pem,
        certs_to_pem, get_cn,
        pem_to_certs,
        policy_from_cert,
        verify_cert_chain,
        )


class EECert(object):
    """
    Generic class for EE certificate.
    """
    def __init__(self, pem):
        self.pem = pem
        self.domain_name = ""
        self.chains = []
        self._parse(pem)

    def _parse(self, pem):
        pass

    def verify_chains(self, trusted_certs):
        print("verify_chains")
        res = []
        for chain in self.chains:
            pem = certs_to_pem(chain)
            if verify_cert_chain(pem, trusted_certs):
                res.append(ChainProperties(chain))
        return res

    def __repr__(self):
        tmp = ["Domain: %s\n" % self.domain_name]
        for chain in self.chains:
            tmp.append("Chain: %s\n" % chain)
        # tmp.append("Policy: %s\n" % self.policy)
        return "".join(tmp)


class MSC(EECert):
    """
    Multi-signature certificate.
    """
    def __init__(self, pem):
        self.policy_binding = None
        super().__init__(pem)
        assert self._verify_msc_integrity()  # TODO(PSz): raise an exception

    def _parse(self, pem):
        certs = pem_to_certs(pem)
        if not certs:
            return
        self.domain_name = get_cn(certs[0])
        self.policy_binding = certs[-1]  # The last cert is a policy binding
        # Check CN of policy binding
        assert get_cn(self.policy_binding) == self.domain_name  # TODO(PSz): exception
        # Parse certificate chains
        chain = []
        for cert in reversed(certs[:-1]):
            chain.insert(0, cert)
            # End of the chain
            if get_cn(cert) == self.domain_name:
                self.chains.insert(0, chain)
                chain = []
        assert not chain  # TODO(PSz): unterminated chain, raise an exception

    def _verify_msc_integrity(self):
        print("_verify_msc_integrity")
        # Skip the policy binding (the last element)
        pem = CERT_SEP.join(self.pem.split(CERT_SEP)[:-1])
        # Generate policy binding from the pem
        pi, _ = binding_from_pem(pem)
        # Compare with the MSC's policy binding
        try:
            exts = self.policy_binding.extensions.get_extension_for_class(CertificatePolicies)
            return pi == exts.value
        except ExtensionNotFound:
            logging.error("Certificate binding not found.")
            return False

    def __repr__(self):
        tmp = ["MSC\n"]
        tmp.append(super().__repr__())
        tmp.append("Policy Binding: %s\n" % self.policy_binding)
        return "".join(tmp)


class SCP(EECert):
    """
    Subject certificate policy.
    """
    def __init__(self, pem):
        self.policy = b""
        super().__init__(pem)

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

    def __repr__(self):
        tmp = ["SCP\n"]
        tmp.append(super().__repr__())
        tmp.append("Policy: %s\n" % self.policy)
        return "".join(tmp)
