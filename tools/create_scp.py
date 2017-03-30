#!/usr/bin/python3
import sys

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from lib.x509 import create_x509cert

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
        return x509.load_pem_x509_certificate(f.read(), default_backend())

def policy_from_file(path):
    # PSz: that should be an extension
    with open(path) as f:
        return f.read()


if __name__ == "__main__":
    if len(sys.argv) < 6 or len(sys.argv) % 2:
        # Certificates and keys are in PEM format.
        print("%s domain pubkey policy CA1.crt CA1.key CA2.crt CA2.key ... "
              % sys.argv[0])
        sys.exit()
    domain = sys.argv[1]
    pubkey = pubkey_from_file(sys.argv[2])
    policy = policy_from_file(sys.argv[3])
    # Create certificates
    i = 4
    while i < len(sys.argv):
        ca_cert = cert_from_file(sys.argv[i])
        ca_privkey = privkey_from_file(sys.argv[i+1])
        create_x509cert(domain, pubkey, ca_cert, ca_privkey)
        i += 2



