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

EEPKI_PORT = 9088
DEFAULT_CERT_VALIDITY = 120  # In days.
POLICY_OID = "1.2.34.56.1"
POLICY_BINDIND_OID = "1.2.34.56.2"
CERT_SEP = b'-----BEGIN CERTIFICATE-----\n'
DAY = 3600*24


# TODO(PSz): introduce more granular classes
class EEPKIError(Exception):
    pass


class EEPKIParseError(EEPKIError):
    pass

class SecLevel(object):
    LOW = 0
    MEDIUM = 1
    HIGH = 2


class ValidationResult(object):
    ACCEPT = 0
    SOFTFAIL = 1
    HARDFAIL = 2


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
    FAIL_PROOF_EXP = 'FAIL_PROOF_EXP'
    FAIL_POL_VER = 'FAIL_POL_VER'
    FAIL_LOG = 'FAIL_LOG'
    INHERITANCE = 'INHERITANCE'
    # Categorized sets (helpful in parameters inheritance)
    INTERSECT_SET = [LOG_LIST, CA_LIST]
    LESS_SET = [CERT_TH, CERT_SEC, TLS_SEC, FAIL_CERT_TH, FAIL_TLS_SEC,
                FAIL_PROOF_EXP, FAIL_POL_VER, UP_CA_MIN, UP_CA_TH, UP_COP_UNLINKED,
                UP_COP_UNTRUSTED]
    MORE_SET = [LOG_TIMEOUT, MAX_PATH_LEN, MAX_LIFETIME]
    BOOL_SET = [EV_ONLY, WILDCARD_FORBIDDEN]


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
    PolicyFields.TLS_SEC: SecLevel.LOW,
    PolicyFields.UP_CA_MIN: 1,
    PolicyFields.UP_CA_TH: 1,
    PolicyFields.UP_COP_UNTRUSTED: DAY*7,
    PolicyFields.UP_COP_UNLINKED: DAY*7,
    PolicyFields.FAIL_CERT_TH: ValidationResult.SOFTFAIL,
    PolicyFields.FAIL_TLS_SEC: ValidationResult.SOFTFAIL,
    PolicyFields.FAIL_PROOF_EXP: ValidationResult.SOFTFAIL,
    PolicyFields.FAIL_POL_VER: ValidationResult.SOFTFAIL,
    PolicyFields.FAIL_LOG: ValidationResult.SOFTFAIL,
    PolicyFields.INHERITANCE: [],
    }


class MsgFields(object):
    #FIXME(PSz): getting too big, split it.
    # Generic
    TYPE = "type"
    ENTRY = "entry"
    REV = "rev"
    MSC = "msc"
    SCP = "scp"
    CERT = "cert"
    DNAME = "dname"
    # lib/tree_entries.py
    REV_ENTRY = "rev_entry"
    MSC_ENTRY = "msc_entry"
    SCP_ENTRY = "scp_entry"
    CERT_ENTRY = "cert_entry"
    POLICY_ENTRY = "policy_entry"
    ROOTS_ENTRY = "roots_entry"
    POLICY_ROOT = "policy_root"
    CERT_ROOT = "cert_root"
    SUBROOT = "subroot"
    # lib/tree_proofs.py
    CHAIN = "chain"
    ABSENCE_PROOF = "absence_proof"
    PROOF1 = "proof1"
    PROOF2 = "proof2"
    PRESENCE_PROOF = "presence_proof"
    POLICY_PROOF = "policy_proof"
    EEPKI_PROOF = "eepki_proof"
    # Requests/Responses
    SIGNED_ROOT = "signed_root"
    ERROR_MSG = "error_msg"
    ADD_MSG = "add_msg"
    ACCEPT_MSG = "accept_msg"
    GET_UPDATE_MSG = "get_update_msg"
    UPDATE_MSG = "update_msg"
    PROOF_MSG = "proof_msg"
    # Message fields
    SIGNATURE = "signature"
    DESCRIPTION = "description"
    TIMESTAMP = "timestamp"
    HASH = "hash"
