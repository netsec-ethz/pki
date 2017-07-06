#!/bin/bash
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

echo
echo "Make sure that SCION infrastructure is running!!"
# start logs
PYTHONPATH=..:../scion:../scion/python python3 log/server.py log1 >/dev/null 2>&1 &
PYTHONPATH=..:../scion:../scion/python python3 log/server.py log2 >/dev/null 2>&1 &
PYTHONPATH=..:../scion:../scion/python python3 log/server.py log3 >/dev/null 2>&1 &
sleep 1
# and monitors
PYTHONPATH=..:../scion:../scion/python python3 log/monitor.py monitor1 >/dev/null 2>&1 &
PYTHONPATH=..:../scion:../scion/python python3 log/monitor.py monitor2 >/dev/null 2>&1 &
PYTHONPATH=..:../scion:../scion/python python3 log/monitor.py monitor3 >/dev/null 2>&1 &
sleep 2
# run tests with client
PYTHONPATH=..:../scion:../scion/python python3 log/client.py 2-25 127.2.2.2
# and kill
pkill -P $$
