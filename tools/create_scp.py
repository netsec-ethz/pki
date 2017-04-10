#!/usr/bin/python3
import sys

from lib.utils import (cert_from_file, policy_from_file,
                       privkey_from_file, pubkey_from_file)
from lib.x509 import create_x509cert


if __name__ == "__main__":
    if len(sys.argv) < 6 or len(sys.argv) % 2:
        # Certificates and keys are in PEM format.
        print("%s domain pubkey policy CA1.crt CA1.key CA2.crt CA2.key ... "
              % sys.argv[0])
        sys.exit()
    domain = sys.argv[1]
    pubkey = pubkey_from_file(sys.argv[2])
    policy_ext = policy_from_file(sys.argv[3])
    # Create certificates
    i = 4
    pem = b""
    while i < len(sys.argv):
        ca_cert = cert_from_file(sys.argv[i])
        ca_privkey = privkey_from_file(sys.argv[i+1])
        pem += create_x509cert(domain, pubkey, ca_cert,
                               ca_privkey, exts=[policy_ext])
        i += 2
    print(pem.decode('utf-8'))

