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

# Generate scion config and create a symlink to CA store and TRC, e.g.,:
# ln -s ~/path_to/scion/gen/CAS/ISD1/
# ln -s ~/path_to/scion/gen/ISD1/AS11/bs1-11-1/certs/ISD1-V0.trc
import os
import random
import string
from collections import defaultdict

from pki.tools.create_keypair import gen_keypair
from pki.tools.create_msc import gen_msc
from pki.tools.create_scp import gen_scp

OUTPUT_DIR = "tmp/"
# All other paths are relative to OUTPUT_DIR
MSC_CAS = ["../ISD1/CA1-3.cert", "../ISD1/CA1-3.key",
           "../ISD1/CA1-2.cert", "../ISD1/CA1-2.key"]
SCP_CAS = ["../ISD1/CA1-1.cert","../ISD1/CA1-1.key",
           "../ISD1/CA1-2.cert", "../ISD1/CA1-2.key"]
POLICY_FILE = "../tools/policy.json"

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

def gen_all(level=5):
    os.chdir(OUTPUT_DIR)
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

if __name__ == "__main__":
    gen_all(5)
