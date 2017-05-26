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


# Test Trees
from pki.lib.tree_entries import *
from pki.lib.trees import *
import copy
import random
import string
from collections import defaultdict

def random_domain_names(level=3, per_level=2, length=2):
    def random_word(length):
       return ''.join(random.choice(string.ascii_lowercase) for i in range(length))
    names = defaultdict(list)
    for level_ in range(level):
        for per_level_ in range(per_level):
            if not level_: # TLD
                names[level_].append(random_word(length))
            else:
                for upper in names[level_-1]:
                    names[level_].append(random_word(length)+"."+upper)
    res = []
    for i in names:
        res += names[i]
    random.shuffle(res)
    return res

scps = []
mscs = []
certs = []
policies = []
for i in random_domain_names()[:1]:
    tmp = copy.copy(scp)
    tmp.pem = b"SCPpem: %s" % bytes(i, "utf-8")
    tmp.domain_name = i
    scps.append(SCPEntry(tmp))
    policies.append(PolicyEntry(tmp.domain_name, tmp))
    #
    tmp = copy.copy(msc)
    tmp.pem = b"MSCpem: %s" % bytes(i, "utf-8")
    tmp.domain_name = i
    mscs.append(MSCEntry(tmp))
    certs.append(CertificateEntry(tmp))

random.shuffle(certs)
chrontree = ConsistencyTree(scps+mscs)
# print(chrontree)
certtree = CertificateTree(certs)
print(certtree)
polsub = PolicySubTree(policies)
print(polsub)

print("\n\n\n")
poltree = PolicyTree(policies)
