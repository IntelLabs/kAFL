#!/usr/bin/env python3
#
# Copyright 2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright 2021 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Pretty-Print msgpack files produced by kAFL
"""

import os
import sys

import msgpack
from pprint import pprint

def read_binary_file(filename):
    with open(filename, 'rb') as f:
        return f.read()

for arg in sys.argv[1:]:
    pprint(msgpack.unpackb(read_binary_file(arg), strict_map_key=False))
