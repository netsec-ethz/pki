#!/usr/bin/python3
import sys

from lib.utils import (binding_from_pem, cert_from_file,
                       privkey_from_file, pubkey_from_file)
from lib.x509 import create_x509cert


if __name__ == "__main__":
    if len(sys.argv) < 6 or len(sys.argv) % 2:
        # Certificates and keys are in PEM format.
        print("%s domain pubkey policy.key CA1.crt CA1.key CA2.crt CA2.key ... "
              % sys.argv[0])
        sys.exit()
    domain = sys.argv[1]
    pubkey = pubkey_from_file(sys.argv[2])
    policy_privkey = privkey_from_file(sys.argv[3])
    # Create certificates
    i = 4
    pem = b""
    while i < len(sys.argv):
        ca_cert = cert_from_file(sys.argv[i])
        ca_privkey = privkey_from_file(sys.argv[i+1])
        pem += create_x509cert(domain, pubkey, ca_cert, ca_privkey)
        i += 2
    # Create self signed cert with a policy binding
    binding = binding_from_pem(pem)
    pem += create_x509cert(domain, pubkey, None, policy_privkey, exts=[binding])
    print(pem.decode('utf-8'))
