#!/bin/bash
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
import cbor
import ipaddress
import os
import random
import string
import sys
from collections import defaultdict

from pki.lib.defines import CONF_DIR, CONF_FILE, OUTPUT_DIR
from pki.tools.create_keypair import gen_keypair
from pki.tools.create_msc import gen_msc
from pki.tools.create_scp import gen_scp

from lib.crypto.asymcrypto import generate_sign_keypair


# All other paths are relative to OUTPUT_DIR
MSC_CAS = ["../ISD1/CA1-3.cert", "../ISD1/CA1-3.key",
           "../ISD1/CA1-2.cert", "../ISD1/CA1-2.key"]
SCP_CAS = ["../ISD1/CA1-1.cert","../ISD1/CA1-1.key",
           "../ISD1/CA1-2.cert", "../ISD1/CA1-2.key"]
POLICY_FILE = "../tools/policy.json"
# ASes for config generation
ASes = ["1-10", "1-17", "1-18"]

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

def gen_certs(level=5):
    os.system("rm *.msc *.scp *.key *.pub")
    for domain_name in random_domain_names(level):
        # Generate keypairs
        gen_keypair(domain_name + "-scp")
        gen_keypair(domain_name + "-msc")
        scp_pub = "%s-scp.pub" % domain_name
        msc_pub = "%s-msc.pub" % domain_name
        scp_key = "%s-scp.key" % domain_name
        # Generate MSC
        argv = [domain_name, msc_pub, scp_key] + MSC_CAS
        gen_msc(argv)
        # Generate SCP
        argv = [domain_name, scp_pub, POLICY_FILE] + SCP_CAS
        gen_scp(argv)
        print("Generated keys and certs for %s" % domain_name)

def gen_config(threshold, log_no, monitor_no):
    try:
        os.mkdir('conf/')
    except FileExistsError:
        pass
    os.system("rm -f " + CONF_DIR + CONF_FILE + " %s*.priv" % CONF_DIR)
    #
    dict_ = {"threshold": threshold}
    dict_["logs"] = {}
    dict_["monitors"] = {}
    # First logs
    for i in range(1, log_no + 1):
        log_id = "log%d" % i
        isd_as = random.choice(ASes)
        ip = str(ipaddress.ip_address("127.0.1.0") + i)
        pub, priv = generate_sign_keypair()
        dict_["logs"][log_id] = [isd_as, ip, pub]
        with open(CONF_DIR + "%s.priv" % log_id, "wb") as f:
            f.write(priv)
    # Then monitors
    for i in range(1, monitor_no + 1):
        monitor_id = "monitor%d" % i
        isd_as = random.choice(ASes)
        ip = str(ipaddress.ip_address("127.0.2.0") + i)
        pub, priv = generate_sign_keypair()
        dict_["monitors"][monitor_id] = [isd_as, ip, pub]
        with open(CONF_DIR + "%s.priv" % monitor_id, "wb") as f:
            f.write(priv)
    # Save on disc
    blob = cbor.dumps(dict_)
    with open(CONF_DIR + CONF_FILE, "wb") as f:
        f.write(blob)
    print("config generated")

# Generate scion config and create a symlink to CA store and TRC, e.g.,:
# ln -s ~/path_to/scion/gen/CAS/ISD1/
# ln -s ~/path_to/scion/gen/ISD1/AS11/bs1-11-1/certs/ISD1-V0.trc
if __name__ == "__main__":
    os.chdir(OUTPUT_DIR)
    gen_certs(5)
    gen_config(3, 3, 3)
