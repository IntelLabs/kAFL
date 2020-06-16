#!/usr/bin/env python3
#
# Copyright 2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright 2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Pretty-Pring msgpack files produced by kAFL
"""

import os
import sys

import msgpack
from pprint import pprint

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)) + "/../kAFL-Fuzzer/")
from common.util import read_binary_file

for arg in sys.argv[1:]:
    pprint(msgpack.unpackb(read_binary_file(arg), raw=False, strict_map_key=False))
