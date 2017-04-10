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
import datetime
import os

from lib.defines import DEFAULT_CERT_VALIDITY

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def random_serial_number():
    # FIXME(PSz): can be replaced by x509.random_serial_numer() when we have
    # newer version of cryptography.io (>=1.6)
    return int.from_bytes(os.urandom(20), byteorder="big")

def create_x509cert(domain_name, pubkey, ca_cert, ca_privkey, exts=None):
    """
    exts: list of the (extension, critical_flag) tuples.
    """
    one_day = datetime.timedelta(1, 0, 0)
    now = datetime.datetime.today()
    builder = x509.CertificateBuilder()
    x509_dn = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain_name)])
    builder = builder.subject_name(x509_dn)
    if ca_cert:
        builder = builder.issuer_name(ca_cert.issuer)
    else:  # When CA cert is not given, then it is self signed
        builder = builder.issuer_name(x509_dn)
    builder = builder.not_valid_before(now - one_day)
    builder = builder.not_valid_after(now + one_day * DEFAULT_CERT_VALIDITY)
    builder = builder.serial_number(random_serial_number())
    builder = builder.public_key(pubkey)
    # Add standard extensions
    builder = builder.add_extension(
        x509.SubjectAlternativeName([x509.DNSName(domain_name)]),
        critical=False)
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True)
    # Add passed extensions (i.e., policy or policy binding)
    for (ext, is_critical) in exts or []:
        builder = builder.add_extension(ext, critical=is_critical)
    certificate = builder.sign(private_key=ca_privkey,
        algorithm=hashes.SHA256(), backend=default_backend())
    # return the chain
    pem = certificate.public_bytes(encoding=serialization.Encoding.PEM)
    if ca_cert:
        pem += ca_cert.public_bytes(encoding=serialization.Encoding.PEM)
    return pem

