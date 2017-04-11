#!/bin/bash
mkdir tmp
cd tmp
PYTHONPATH=../ ../tools/create_keypair.py a.com-scp
PYTHONPATH=../ ../tools/create_keypair.py a.com-msc
PYTHONPATH=../ ../tools/create_msc.py a.com a.com-msc.pub a.com-scp.key ../ISD1/CA1-3.cert ../ISD1/CA1-3.key ../ISD1/CA1-2.cert ../ISD1/CA1-2.key >msc.cert
echo MSC created
PYTHONPATH=../ ../tools/create_scp.py a.com a.com-scp.pub ../tools/policy.json ../ISD1/CA1-1.cert ../ISD1/CA1-1.key ../ISD1/CA1-2.cert ../ISD1/CA1-2.key >scp.cert
echo SCP created
cd ..
