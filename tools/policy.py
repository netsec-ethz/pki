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
import json

from pki.lib.defines import DEFAULT_POLICY, PolicyFields as PF

d = DEFAULT_POLICY
d[PF.LOG_LIST] = ["Log1", "Log2"]
d[PF.CA_LIST] = ["CA1", "CA2"]
d[PF.INHERITANCE] = [PF.CA_LIST, PF.FAIL_CERT_TH]

if __name__ == "__main__":
    print(json.dumps(json.loads(json.dumps(DEFAULT_POLICY))))
