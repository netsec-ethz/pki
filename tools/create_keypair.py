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
import sys

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def gen_keypair(name):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048,
                                           backend=default_backend())
    with open("%s.key" % name, "wb") as f:
        pem = private_key.private_bytes(encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption())
        f.write(pem)

    public_key = private_key.public_key()
    with open("%s.pub" % name, "wb") as f:
        pem = public_key.public_bytes(encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)
        f.write(pem)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("%s name" % sys.argv[0])
        sys.exit(-1)
    gen_keypair(sys.argv[1])

