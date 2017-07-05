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
import os
import sys
import copy
import glob
import random
import string
import threading
import time
from collections import defaultdict

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization

from pki.generate import CONF_DIR, CONF_FILE, OUTPUT_DIR
from pki.lib.defines import EEPKIError, SecLevel, ValidationResult
from pki.lib.cert import MSC, SCP
from pki.log.conf import Conf
from pki.log.log import Log
from pki.log.client import LogClient
from pki.log.monitor import LogMonitor
from pki.log.server import LogServer
from pki.lib.verifier import verify
from pki.lib.x509 import certs_to_pem, pem_to_certs
from pki.lib.trees import *
from pki.lib.tree_entries import *
from pki.lib.tree_proofs import EEPKIProof

# SCION
from lib.crypto.trc import TRC
from lib.packet.host_addr import haddr_parse
from lib.packet.scion_addr import ISD_AS, SCIONAddr

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

def load_mscs_scps():
    mscs = {}
    scps = {}
    old_dir = os.getcwd()
    os.chdir(OUTPUT_DIR)
    for name in glob.glob("*.msc"):
        domain_name = name[:-4]
        # Load MSC
        with open(name, "rb") as f:
            pem = f.read()
        msc = MSC(MSC(pem).pack())
        mscs[domain_name] = msc
        assert msc.pack() == pem, "parse()/pack() failed"
        # and corresponding SCP
        with open(domain_name + ".scp", "rb") as f:
            pem = f.read()
        scp = SCP(SCP(pem).pack())
        scps[domain_name] = scp
        assert scp.pack() == pem, "parse()/pack() failed"
    os.chdir(old_dir)
    return mscs, scps

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
    print("Testing parsing/packing")
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

def test_proofs(log, mscs, scps):
    print("Testing proofs")
    # Prepare validation vectors
    vectors = []
    root, _ = log.get_root_entries()
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

def test_log_local(mscs, scps):
    print("Starting log and building trees")
    log = Log()
    all_ = scps + mscs
    random.shuffle(all_)
    for e in all_:
        log.add(e)
        log.build()  # test building for each node
    log.build()
    # Policy trees should be consistent
    random.shuffle(all_)
    assert log.policy_tree.get_root() == Log(all_).policy_tree.get_root()
    return log

def test_infrastructure(mscs, scps):
    print("\nStarting infrastructure test. SCION must be running!!!")
    # First read configuration
    conf_file = OUTPUT_DIR + CONF_DIR + CONF_FILE
    conf = Conf(conf_file)
    # next, run log servers
    for id_ in conf.logs:
        priv_key_file = OUTPUT_DIR + CONF_DIR + id_ + ".priv"
        log_serv = LogServer(conf_file, priv_key_file, id_)
        threading.Thread(target=log_serv.run, name="LogServer", daemon=True).start()
        time.sleep(0.2)
        print("Starting: %s" % id_)
    # and monitors
    for id_ in conf.monitors:
        priv_key_file = OUTPUT_DIR + CONF_DIR + id_ + ".priv"
        monitor = LogMonitor(conf_file, priv_key_file, id_)
        threading.Thread(target=monitor.run, name="LogMonitor", daemon=True).start()
        print("Starting: %s" % id_)
        time.sleep(1)
    # finally, start client
    cli_addr = SCIONAddr.from_values(ISD_AS("2-25"), haddr_parse(1, "127.2.2.2"))
    cli = LogClient(cli_addr, conf_file)
    rnd_log = random.choice(list(conf.logs))
    print("Connecting to %s" % rnd_log)
    cli.connect(rnd_log)
    all_ = scps + mscs
    random.shuffle(all_)
    print("Submitting SCPs and MSCs to %s" % rnd_log)
    i = 1
    for obj in all_:
        print(i, cli.submit(obj))
        i += 1
    cli.close()
    # Now take a root of every log and confirm it by every monitor
    for log_id in conf.logs:
        print("Connecting to %s" % log_id)
        cli.connect(log_id)
        root = cli.get_root()
        cli.close()
        for monitor_id in conf.monitors:
            print("Connecting to %s" % monitor_id)
            cli.connect(monitor_id)
            print(cli.confirm_root(root), end="\n\n")
            cli.close()


if __name__ == "__main__":
    # PYTHONPATH=..:../scion ./tests.py tmp/msc.cert tmp/scp.cert ISD1-V0.trc
    if len(sys.argv) != 2:
        print("%s <TRC>" % sys.argv[0])
        sys.exit(-1)
    with open(sys.argv[1], "r") as f:
        trc = TRC.from_raw(f.read())
    # Load generated objects
    mscs, scps = load_mscs_scps()
    for domain_name in mscs:
        msc = mscs[domain_name]
        scp = scps[domain_name]
        # Verify MSC
        verifier(msc, scp, trc, domain_name)
        # Test basic packing and parsing
        test_pack_parse(msc, scp)
    mscsl = list(mscs.values())
    scpsl = list(scps.values())
    # Test log operations
    log = test_log_local(mscsl, scpsl)
    # Test proofs
    test_proofs(log, mscsl, scpsl)
    # Test log with network
    test_infrastructure(mscsl, scpsl)
