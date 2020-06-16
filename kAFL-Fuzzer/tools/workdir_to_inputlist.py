"""
Copyright (C) 2019  Sergej Schumilo, Cornelius Aschermann, Tim Blazytko

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

# !/usr/bin/env python2
import glob
import sys

import msgpack
import os

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)) + "/../")
from common.util import read_binary_file

if len(sys.argv) < 2:
    print
    "[*] Too few arguments!"
    sys.exit()

workdir = sys.argv[1]

# fuzzing start time
start_times = []

for slave_stats_path in glob.glob(workdir + "/slave_stats_*"):
    slave_stats = msgpack.unpackb(read_binary_file(slave_stats_path))
    start_time = slave_stats['start_time']
    start_times.append(start_time)

start_time = min(start_times)

for file_path in glob.glob(workdir + "/corpus/*/*"):
    file_path = "{}/{}".format(os.getcwd(), file_path)
    input_id = os.path.basename(file_path).replace("payload", "")
    metadata_path = workdir + "/metadata/node{}".format(input_id)
    metadata = msgpack.unpackb(read_binary_file(metadata_path))

    timestamp = metadata["info"]["time"] - start_time

    print
    "{};{}".format(file_path, timestamp)
