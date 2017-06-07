#!/usr/bin/python3
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
import sys

from pki.lib.x509 import cert_from_file, privkey_from_file, pubkey_from_file
from pki.lib.x509 import binding_from_pem, create_x509cert


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
    print(pem.decode('utf-8'), end='')
