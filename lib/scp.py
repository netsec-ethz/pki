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
import logging

from cryptography.x509 import CertificatePolicies

from lib.defines import CERT_SEP, SecLevel
from lib.x509 import (binding_from_pem, certs_to_pem, get_cn, pem_to_certs,
        policy_from_cert, verify_cert_chain)
