#!/usr/bin/python3
import sys

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("%s name" % sys.argv[0])
        sys.exit()

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048,
                                           backend=default_backend())
    with open("%s.key" % sys.argv[1], "wb") as f:
        pem = private_key.private_bytes(encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption())
        f.write(pem)
    print("%s.key created" % sys.argv[1])

    public_key = private_key.public_key()
    with open("%s.pub" % sys.argv[1], "wb") as f:
        pem = public_key.public_bytes(encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)
        f.write(pem)
    print("%s.pub created" % sys.argv[1])


