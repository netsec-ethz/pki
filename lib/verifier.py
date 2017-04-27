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
import copy
import logging

from .defines import DEFAULT_POLICY, ValidationResult, SecLevel, PolicyFields as PF
from .x509 import get_cn, cert_from_der, certs_to_pem


def _get_trusted_pems(trc, ca_list=None):
    """
    Returns list of trusted certificates (PEM) from TRC.
    List is filtered by ca_list (if set).
    """
    pems = []
    for ca, der in trc.root_cas.items():
        if (ca_list is not None) and (ca not in ca_list):
            logging.warning("%s not in %s" % (ca, ca_list))
            continue
        # Convert DER to PEM
        pems.append(certs_to_pem([cert_from_der(der)]))
    return pems

def verify(domain_name, msc, scps, proof, trc, tls_sec):
    # First pre-validate
    if domain_name != msc.domain_name:  # TODO(PSz): handle multiple DNs
        logging.error("Domain name mismatch: %s != %s" % (domain_name, msc.domain_name))
        return ValidationResult.HARDFAIL
    if not _verify_proof(msc, scps, proof):
        logging.error("Proof verification failed")
        return ValidationResult.HARDFAIL
    if not _verify_scps(domain_name, scps, trc):
        logging.error("SCPs verification failed")
        return ValidationResult.HARDFAIL
    # Determine the final policy
    p = _determine_policy(domain_name, scps, trc)
    results = [ValidationResult.ACCEPT]  # Accepted if no error will occur
    if not _verify_msc(domain_name, msc, p, trc):
        logging.warning("_verify_msc(): CERT_TH not met")
        results.append(p[PF.FAIL_CERT_TH])
    if tls_sec < p[PF.TLS_SEC]:
        results.append(p[PF.FAIL_TLS_SEC])
    if False:  # TODO(PSz): if proof.is_expired():
        results.append(p[PF.FAIL_PROOF_EXP])
    if False:  # TODO(PSz): if proof.log not in p[PF.LOG_LIST]:
        results.append(p[PF.FAIL_LOG])
    # Return the most severe result
    print(results)
    return max(results)

def _verify_proof(msc, scps, proof):
    """
    Verify whether the proof is fresh and matches the MSC and SCP.
    """
    return True

def _verify_scps(domain_name, scps, trc):
    """
    Verify whether SCPs matches the TRC (trusted CAs and threshold number).
    """
    trusted = _get_trusted_pems(trc)
    tmp_name = "." + domain_name
    for scp in scps:
        # Verify certificate chains in SCP
        res = scp.verify_chains(trusted)
        # Check whether successful results are >= threshold
        print(res)
        if len(res) < trc.quorum_eepki:
            logging.error("quroum_eepki not satisfied: %d < %d for %s" %
                          (len(res), trc.quorum_eepki, scp))
            return False
        # Check domain names and their order
        if ("." + scp.domain_name) not in tmp_name:
            logging.error("incorrect domain name or its order: %s" % scp.domain_name)
            return False
        tmp = "." + scp.domain_name
    return True

def _verify_msc(domain_name, msc, p, trc):
    """
    Verify whether MSC matches the SCP and domain name.
    """
    # First check whether domain name matches
    if domain_name != msc.domain_name:
        logging.error("%s != %s" % (domain_name, msc.domain_name))
        return (False, ValidationResult.HARDFAIL)

    # Verify MSC's chains based on the SCP's trusted CAs
    trusted = _get_trusted_pems(trc, p[PF.CA_LIST])
    # Get list of ValidationResults for successfuly validated chains
    results = msc.verify_chains(trusted)
    print(results)
    # Validate results according to the policy
    s = set()
    for res in results:
        if (res.sec_lvl >= p[PF.CERT_SEC] and
            res.path_len <= p[PF.MAX_PATH_LEN] and
            res.valid_for <= p[PF.MAX_LIFETIME] and
            (res.ev or not p[PF.EV_ONLY]) and
            (not res.wildcard or not p[PF.WILDCARD_FORBIDDEN])):
            s.add(res.ca)
    print(s)
    return len(s) >= p[PF.CERT_TH]

def _determine_policy(domain_name, scps, trc):
    """
    Determine final policy parameters for domain, based on SCPs and TRC
    """
    p = _get_default_policy(trc)
    if not scps:
        return p
    # Copy domain's policy (if exists)
    if scps and domain_name == scps[0].domain_name:
        for key, value in scps[0].policy.items():
            p[key] = value
    # Inherit values from other policies
    for scp in scps[1:]:
        inherit_params(p, scp.policy)
    return p

def _get_default_policy(trc):
    # Take template and populate it by CAs and logs from TRC
    p = copy.copy(DEFAULT_POLICY)
    p[PF.CA_LIST] = trc.root_cas.keys()
    p[PF.LOG_LIST] = trc.pki_logs.keys()
    return p

def inherit_params(p, upper_policy):
    """
    Modifies p according to inheritance parameters of upper_policy
    """
    if PF.INHERITANCE not in upper_policy:
        return
    # Something to inherit
    for key in upper_policy[PF.INHERITANCE]:
        if key in PF.INTERSECT_SET:  # Inherit set elements (i.e., output intersection)
            p[key] = list(set(p[key]).intersection(upper_policy[key]))
        elif key in PF.LESS_SET:  # Inherit higher parameter
            if p[key] < upper_policy[key]:
                p[key] = upper_policy[key]
        elif key in PF.MORE_SET:  # Inherit lower parameter
            if p[key] > upper_policy[key]:
                p[key] = upper_policy[key]
        elif key in PF.BOOL_SET:
            if upper_policy[key]:
                p[key] = upper_policy[key]
    return
