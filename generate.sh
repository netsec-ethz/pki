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

# Generate scion config and create a symlink to CA store:
# ln -s ~/path_to/scion/gen/CAS/ISD1/
rm -rf tmp
mkdir tmp
cd tmp
PYTHONPATH=../../:../../scion ../tools/create_keypair.py a.com-scp
PYTHONPATH=../../:../../scion ../tools/create_keypair.py a.com-msc
PYTHONPATH=../../:../../scion ../tools/create_msc.py a.com a.com-msc.pub a.com-scp.key ../ISD1/CA1-3.cert ../ISD1/CA1-3.key ../ISD1/CA1-2.cert ../ISD1/CA1-2.key
PYTHONPATH=../../:../../scion ../tools/create_scp.py a.com a.com-scp.pub ../tools/policy.json ../ISD1/CA1-1.cert ../ISD1/CA1-1.key ../ISD1/CA1-2.cert ../ISD1/CA1-2.key
cd ..
