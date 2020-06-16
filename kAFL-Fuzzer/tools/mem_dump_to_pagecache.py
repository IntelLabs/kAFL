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

import sys
import struct

if (len(sys.argv) != 3):
    print("Usage: python mem_dump_to_pagecache.py $base_offset $dump_file")
    exit(0)

start = int(sys.argv[1], 16)
input = sys.argv[2]
content = open(input, 'r').read()
with open(input + ".pagecache.dump", "w") as f:
    pad_length = 0
    if len(content) % 4096 != 0:
        pad_length = 4096 - len(content) % 4096
    num_pages = (len(content) + pad_length) / 4096
    f.write(content + "\0" * pad_length)

with open(input + ".pagecache.addr", "w") as f:
    for i in range(0, num_pages):
        f.write(struct.pack("Q", start + i * 4096))
