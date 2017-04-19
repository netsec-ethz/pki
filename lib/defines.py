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

DEFAULT_CERT_VALIDITY = 120  # In days.
POLICY_OID = "1.2.34.56.1"
POLICY_BINDIND_OID = "1.2.34.56.2"
CERT_SEP = b'-----BEGIN CERTIFICATE-----\n'


class SecLevel(object):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class FailCase(object):
    SOFT = "soft"
    HARD = "hard"


class PolicyFields(object):
    POLICY_VERSION = 'POLICY_VERSION'
    LOG_LIST = 'LOG_LIST'
    LOG_TIMEOUT = 'LOG_TIMEOUT'
    CA_LIST = 'CA_LIST'
    CERT_TH = 'CERT_TH'
    REV_KEY = 'REV_KEY'
    EV_ONLY = 'EV_ONLY'
    MAX_PATH_LEN = 'MAX_PATH_LEN'
    WILDCARD_FORBIDDEN = 'WILDCARD_FORBIDDEN'
    MAX_LIFETIME = 'MAX_LIFETIME'
    CERT_SEC = 'CERT_SEC'
    TLS_SEC = 'TLS_SEC'
    UP_CA_MIN = 'UP_CA_MIN'
    UP_CA_TH = 'UP_CA_TH'
    UP_COP_UNTRUSTED = 'UP_COP_UNTRUSTED'
    UP_COP_UNLINKED = 'UP_COP_UNLINKED'
    FAIL_CERT_TH = 'FAIL_CERT_TH'
    FAIL_TLS_SEC = 'FAIL_TLS_SEC'
    FAIL_LOG_EXP = 'FAIL_LOG_EXP'
    FAIL_POL_VER = 'FAIL_POL_VER'
    FAIL_LOG_PROOF = 'FAIL_LOG_PROOF'
    INHERITANCE = 'INHERITANCE'

DAY = 3600*24
DEFAULT_POLICY = {
        PolicyFields.POLICY_VERSION: 1,
        PolicyFields.LOG_LIST: [],
        PolicyFields.LOG_TIMEOUT: DAY*7,
        PolicyFields.CA_LIST: [],
        PolicyFields.CERT_TH: 1,
        PolicyFields.REV_KEY: True,
        PolicyFields.EV_ONLY: False,
        PolicyFields.MAX_PATH_LEN: 5,
        PolicyFields.WILDCARD_FORBIDDEN: False,
        PolicyFields.MAX_LIFETIME: DAY*365*3,
        PolicyFields.CERT_SEC: SecLevel.LOW,
        PolicyFields.TLS_SEC: SecLevel.MEDIUM,
        PolicyFields.UP_CA_MIN: 1,
        PolicyFields.UP_CA_TH: 1,
        PolicyFields.UP_COP_UNTRUSTED: DAY*7,
        PolicyFields.UP_COP_UNLINKED: DAY*7,
        PolicyFields.FAIL_CERT_TH: FailCase.HARD,
        PolicyFields.FAIL_TLS_SEC: FailCase.SOFT,
        PolicyFields.FAIL_LOG_EXP: FailCase.HARD,
        PolicyFields.FAIL_POL_VER: FailCase.SOFT,
        PolicyFields.FAIL_LOG_PROOF: FailCase.HARD,
        PolicyFields.INHERITANCE: [],
        }

