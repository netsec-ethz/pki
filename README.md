# pki
End-entity PKI


Requirements:
- (developed and tested on Ubuntu 16.06, python 3.5)
- cryptography.io (pip3 install cryptography)
- pyOpenSSL (apt install python3-openssl)
- merkle (pip3 install merkle)
- PySyncObj (pip3 install pysyncobj)
  (TODO(PSz): to be replaced by our fork with TCP/SCION)
- SCION codebase (currently, SCION with TCP support is at
  https://github.com/pszalach/scion/tree/tcp_fixes2)


References:
- The ARPKI papers:
    - http://www.netsec.ethz.ch/publications/papers/tdsc-arpki.pdf
    - http://www.netsec.ethz.ch/publications/papers/ccsfp200s-cremersA.pdf
- The PoliCert paper:
    - http://www.netsec.ethz.ch/publications/papers/ccsfp512-szalachowskiA.pdf
- The SCION book:
    - http://scion-architecture.net/pdf/SCION-book.pdf
