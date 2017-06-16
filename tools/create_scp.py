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

from pki.lib.x509 import (cert_from_file, create_x509cert, policy_from_file,
                       privkey_from_file, pubkey_from_file)

def gen_scp(argv):
    domain_name = argv[0]
    pubkey = pubkey_from_file(argv[1])
    policy_ext = policy_from_file(argv[2])
    # Create certificates
    i = 3
    pem = b""
    while i < len(argv):
        ca_cert = cert_from_file(argv[i])
        ca_privkey = privkey_from_file(argv[i+1])
        pem += create_x509cert(domain_name, pubkey, ca_cert,
                               ca_privkey, exts=[policy_ext])
        i += 2
    with open("%s.scp" % domain_name, "w") as f:
        f.write(pem.decode('utf-8'))
    print("%s.scp created" % domain_name)


if __name__ == "__main__":
    if len(sys.argv) < 6 or len(sys.argv) % 2:
        # Certificates and keys are in PEM format.
        print("%s domain_name pubkey policy CA1.crt CA1.key CA2.crt CA2.key ... "
              % sys.argv[0])
        sys.exit(-1)
    gen_scp(sys.argv[1:])
