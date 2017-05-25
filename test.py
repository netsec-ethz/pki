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
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
# from cryptography.x509 import load_pem_x509_certificate
from pki.lib.defines import SecLevel, ValidationResult
from pki.lib.x509 import certs_to_pem, pem_to_certs
from pki.lib.cert import MSC, SCP
from pki.lib.verifier import verify

# SCION
from lib.crypto.trc import TRC


if __name__ == "__main__":
    # PYTHONPATH=..:../scion ./test.py tmp/msc.cert tmp/scp.cert ISD1-V0.trc 
    if len(sys.argv) != 4:
        print("%s <MSC> <SCP> <TRC>" % sys.argv[0])
        sys.exit()
    with open(sys.argv[1], "rb") as f:
        pem = f.read()
    msc = MSC(pem)
    print(msc)
    # take trusted_certs as union of TRCs and policy
    trusted_certs = []
    for chain in msc.chains:
        trusted_certs.append(certs_to_pem([chain[-1]]))  # take the last one (CA)
    print(msc.verify_chains(trusted_certs))

    print()
    with open(sys.argv[2], "rb") as f:
        pem = f.read()
    scp = SCP(pem)
    # Update trusted certs
    for chain in scp.chains:
        pem = certs_to_pem([chain[-1]])
        if pem not in trusted_certs:
            trusted_certs.append(pem)  # take the last one (CA)
    print(scp)
    print(scp.verify_chains(trusted_certs))

    with open(sys.argv[3], "r") as f:
        trc = TRC.from_raw(f.read())

    # The final verification step
    res = verify("a.com", msc, [scp], None, trc, SecLevel.MEDIUM)
    if res == ValidationResult.HARDFAIL:
        print("HARDFAIL")
    elif res == ValidationResult.SOFTFAIL:
        print("SOFTFAIL")
    elif res == ValidationResult.ACCEPT:
        print("ACCEPT")
    else:
        print("Unknown res: %s" % res)

