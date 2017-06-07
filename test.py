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

from pki.lib.defines import EEPKIError, SecLevel, ValidationResult
from pki.lib.cert import MSC, SCP
from pki.log.log import Log
from pki.lib.verifier import verify
from pki.lib.x509 import certs_to_pem, pem_to_certs
from pki.lib.tree_entries import *
from pki.lib.tree_proofs import EEPKIProof

# SCION
from lib.crypto.trc import TRC


def verifier(msc, scp, trc, domain_name, sec_lvl=SecLevel.MEDIUM):
    # take trusted_certs as union of TRCs and policy
    trusted_certs = []
    for chain in msc.chains:
        trusted_certs.append(certs_to_pem([chain[-1]]))  # take the last one (CA)
    print(msc.verify_chains(trusted_certs))

    # Update trusted certs
    for chain in scp.chains:
        pem = certs_to_pem([chain[-1]])
        if pem not in trusted_certs:
            trusted_certs.append(pem)  # take the last one (CA)
    print(scp.verify_chains(trusted_certs))

    # The final verification step
    res = verify(domain_name, msc, [scp], None, trc, sec_lvl)
    if res == ValidationResult.HARDFAIL:
        print("HARDFAIL")
    elif res == ValidationResult.SOFTFAIL:
        print("SOFTFAIL")
    elif res == ValidationResult.ACCEPT:
        print("ACCEPT")
    else:
        print("Unknown res: %s" % res)

def test_pack_parse(msc, scp):
    print("testing parsing/packing")
    entry = MSCEntry.from_values(msc)
    assert entry.is_equal(MSCEntry(entry.pack()))
    assert entry.is_equal(build_entry(entry.pack()))
    entry = SCPEntry.from_values(scp)
    assert entry.is_equal(SCPEntry(entry.pack()))
    assert entry.is_equal(build_entry(entry.pack()))
    entry = CertificateEntry.from_values(msc)
    assert entry.is_equal(CertificateEntry(entry.pack()))
    assert entry.is_equal(build_entry(entry.pack()))
    entry = RootsEntry.from_values(b"test1", b"testtwo")
    assert entry.is_equal(RootsEntry(entry.pack()))
    assert entry.is_equal(build_entry(entry.pack()))
    entry = PolicyEntry.from_values(scp.domain_name, scp)
    assert entry.is_equal(PolicyEntry(entry.pack()))
    assert entry.is_equal(build_entry(entry.pack()))
    entry = PolicyEntry.from_values(scp.domain_name)
    assert entry.is_equal(PolicyEntry(entry.pack()))
    assert entry.is_equal(build_entry(entry.pack()))


if __name__ == "__main__":
    # PYTHONPATH=..:../scion ./test.py tmp/msc.cert tmp/scp.cert ISD1-V0.trc
    if len(sys.argv) != 4:
        print("%s <MSC> <SCP> <TRC>" % sys.argv[0])
        sys.exit()
    # Create a MSC and SCP and test basic parsing and packing
    with open(sys.argv[1], "rb") as f:
        pem = f.read()
    msc = MSC(MSC(pem).pack())
    assert msc.pack() == pem, "parse()/pack() failed"

    with open(sys.argv[2], "rb") as f:
        pem = f.read()
    scp = SCP(SCP(pem).pack())
    assert scp.pack() == pem, "parse()/pack() failed"

    with open(sys.argv[3], "r") as f:
        trc = TRC.from_raw(f.read())
    # Verify MSC
    verifier(msc, scp, trc, "a.com")
    # Test basic packing and parsing
    test_pack_parse(msc, scp)


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
domain_names = random_domain_names(level=5)
for i in domain_names:
    tmp = copy.copy(scp)
    tmp.pem = b"SCPpem: %s" % bytes(i, "utf-8")
    tmp.domain_name = i
    scps.append(tmp)
    #
    tmp = copy.copy(msc)
    tmp.pem = b"MSCpem: %s" % bytes(i, "utf-8")
    tmp.domain_name = i
    mscs.append(tmp)

print("Starting log and building trees")
log = Log()
all_ = scps + mscs
random.shuffle(all_)
for e in all_:
    if isinstance(e, MSC):
        log.add_msc(e)
    elif isinstance(e, SCP):
        log.add_scp(e)
    log.build()  # test building for each node
log.build()


print("Testing proofs")
# Prepare validation vectors
vectors = []
root = log.get_root()
for scp, msc in zip(scps, mscs):
    scp_label = SCPEntry.from_values(scp).get_label()
    msc_label = CertificateEntry.from_values(msc).get_label()
    # full, successful validation
    vectors.append((True, scp_label, root, msc_label, False, False))
    # w/o MSC label
    vectors.append((True, scp_label, root, None, False, False))
    vectors.append((False, scp_label, root, None, True, True))
    # # MSC absence
    vectors.append((True, scp_label, root, msc_label[:-1], False, True))
    vectors.append((True, scp_label, root, msc_label+b"0", False, True))
    vectors.append((True, scp_label, root, b"\x00" + msc_label, False, True))
    vectors.append((True, scp_label, root, b"\xff" + msc_label, False, True))
    vectors.append((False, scp_label, root, msc_label[:-1], False, False))
    vectors.append((False, scp_label, root, msc_label+b"0", False, False))
    vectors.append((False, scp_label, root, b"\x00" + msc_label[:-1], False, False))
    vectors.append((False, scp_label, root, b"\xff" + msc_label+b"0", False, False))
    # # SCP absence
    vectors.append((False, scp_label[:-1], root, msc_label[:-1], False, True))
    vectors.append((False, scp_label+"0", root, msc_label+b"0", False, True))
random.shuffle(vectors)
for v in vectors:
    proof = log.get_proof(v[1], v[3])
    try:
        proof.validate(*v[1:])
        res = True
    except EEPKIError as e:
        res = False
    if res != v[0]:
        print("Validation incorrect: ", v, res)
    # Test proof packing/parsing
    assert EEPKIProof(proof.pack()).pack() == proof.pack()
