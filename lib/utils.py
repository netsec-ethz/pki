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

# FIXME(PSz): to be replaced by canonical CBOR
def obj_to_bin(dict_):
    return cbor.dumps(dict_, sort_keys=True)

def bin_to_obj(raw):
    return cbor.loads(raw)

def get_domains(domain_name):
    """
    For a domain name returns sorted list of all domain names included in it.
    For example, for "www.a.com" it returns ['com', 'a.com', www.a.com']
    """
    res = []
    tmp = ""
    for name in reversed(domain_name.split(".")):
        tmp = name + "." + tmp
        res.append(tmp[:-1])
    return res
