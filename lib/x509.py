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
import base64
import datetime
import json
import logging
import os

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import (
        load_der_x509_certificate,
        load_pem_x509_certificate,
        CertificatePolicies,
        ExtensionNotFound,
        ObjectIdentifier,
        PolicyInformation,
        )
from cryptography.x509.oid import NameOID
from OpenSSL import crypto

from pki.lib.defines import (
        CERT_SEP,
        DEFAULT_CERT_VALIDITY,
        POLICY_BINDIND_OID,
        POLICY_OID,
        SecLevel,
        )


class ChainProperties(object):
    """
    Helper class for storing properties of a certificate chain.
    """
    def __init__(self, chain):
        self.chain = chain
        self.leaf_cert = None
        self.ca = None
        self.path_len = 0
        self.sec_lvl = None
        self.ev = None
        self.valid_for = 0
        self.wildcard = None
        if self.chain:
            self.leaf_cert = chain[0]
            self.ca = get_cn(chain[-1])
            self.path_len = len(chain)
            self._set_sec_lvl()
            self._set_ev()
            self._set_validity()
            self._set_wildcard()

    def _set_sec_lvl(self):
        # TODO(PSz)
        self.sec_lvl = SecLevel.MEDIUM

    def _set_ev(self):
        # TODO(PSz)
        self.ev = False

    def _set_validity(self):
        delta = self.leaf_cert.not_valid_after - self.leaf_cert.not_valid_before
        self.valid_for = int(delta.total_seconds())

    def _set_wildcard(self):
        self.wildcard = '*' in get_cn(self.leaf_cert)  # TODO(PSz): check DNSName

    def __repr__(self):
        s = "<ChainProperties: "
        s += "CA: %s, PathLen: %d, SecLvl: %s, EV: %s, ValidFor: %d, Wildcard: %s" %  (self.ca,
            self.path_len, self.sec_lvl, self.ev, self.valid_for, self.wildcard)
        s += ">"
        return s


def random_serial_number():
    # FIXME(PSz): can be replaced by x509.random_serial_numer() when we have a
    # newer version of cryptography.io (>=1.6)
    return int.from_bytes(os.urandom(20), byteorder="big")

def create_x509cert(domain_name, pubkey, ca_cert, ca_privkey, exts=None):
    """
    exts: list of the (extension, critical_flag) tuples.
    """
    one_day = datetime.timedelta(1, 0, 0)
    now = datetime.datetime.today()
    builder = x509.CertificateBuilder()
    x509_dn = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain_name)])
    builder = builder.subject_name(x509_dn)
    if ca_cert:
        builder = builder.issuer_name(ca_cert.issuer)
    else:  # When CA cert is not given, then it is self signed
        builder = builder.issuer_name(x509_dn)
    builder = builder.not_valid_before(now - one_day)
    builder = builder.not_valid_after(now + one_day * DEFAULT_CERT_VALIDITY)
    builder = builder.serial_number(random_serial_number())
    builder = builder.public_key(pubkey)
    # Add standard extensions
    builder = builder.add_extension(
        x509.SubjectAlternativeName([x509.DNSName(domain_name)]),
        critical=False)
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True)
    # Add passed extensions (i.e., policy or policy binding)
    for (ext, is_critical) in exts or []:
        builder = builder.add_extension(ext, critical=is_critical)
    certificate = builder.sign(private_key=ca_privkey,
        algorithm=hashes.SHA256(), backend=default_backend())
    # return the chain
    chain = [certificate]
    if ca_cert:
        chain.append(ca_cert)
    return certs_to_pem(chain)

def verify_cert_chain(chain_pem, trusted_certs):
    cert = crypto.load_certificate(crypto.FILETYPE_PEM, chain_pem.decode('utf-8'))
    # Build store of trusted certificates
    store = crypto.X509Store()
    for _cert in trusted_certs:
        tmp = crypto.load_certificate(crypto.FILETYPE_PEM, _cert.decode('utf-8'))
        store.add_cert(tmp)
    # Prepare context
    ctx = crypto.X509StoreContext(store, cert)
    # Start validation
    try:
        ctx.verify_certificate()
        return True
    except crypto.X509StoreContextError as e:
        logging.error("Certificate validation failed: %s" % e)
        return False

def binding_from_pem(pem):
    # Set binding as non-critical
    is_critical = False
    # Compute hash over the pem (all previous certificates)
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(pem)
    binding = base64.b64encode(digest.finalize()).decode('utf-8')
    pi = x509.PolicyInformation(x509.ObjectIdentifier(POLICY_BINDIND_OID), [binding])
    return CertificatePolicies([pi]), is_critical

def pem_to_certs(pem):
    ret = []
    for cert in pem.split(CERT_SEP)[1:]:  # skip the first, empty element
        ret.append(load_pem_x509_certificate(CERT_SEP + cert, default_backend()))
    return ret

def certs_to_pem(certs):
    pem = b""
    for cert in certs:
        pem += cert.public_bytes(encoding=serialization.Encoding.PEM)
    return pem

def get_cn(cert):
    # TODO(PSz): deprecate CN for leaf MSC certs
    if cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
        return cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    return None

def pubkey_from_file(path):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read(),
                                                 backend=default_backend())

def privkey_from_file(path):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None,
                                                  backend=default_backend())
def cert_from_file(path):
    with open(path, "rb") as f:
        return load_pem_x509_certificate(f.read(), default_backend())

def policy_from_file(path):
    with open(path) as f:
        policy = f.read()
    # Set our policy extension as critical
    is_critical = True
    pi = PolicyInformation(ObjectIdentifier(POLICY_OID), [policy])
    return CertificatePolicies([pi]), is_critical

def policy_from_cert(cert):
    if not cert.extensions:
        return None
    try:
        exts = cert.extensions.get_extension_for_class(CertificatePolicies)
    except ExtensionNotFound:
        return None
    if not exts or not exts.value:
        return None

    for ext in exts.value:
        if ext.policy_identifier == ObjectIdentifier(POLICY_OID):
            if ext.policy_qualifiers:
                return json.loads(ext.policy_qualifiers[0])
    return None

def cert_from_der(der):
    return load_der_x509_certificate(der, default_backend())
