import base64

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import (load_pem_x509_certificate, CertificatePolicies,
                               ObjectIdentifier, PolicyInformation)

from lib.defines import POLICY_BINDIND_OID, POLICY_OID

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

def binding_from_pem(pem):
    # Set binding as non-critical
    is_critical = False
    # Compute hash over the pem (all previous certificates)
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(pem)
    binding = base64.b64encode(digest.finalize()).decode('utf-8')
    pi = PolicyInformation(ObjectIdentifier(POLICY_BINDIND_OID), [binding])
    return CertificatePolicies([pi]), is_critical
