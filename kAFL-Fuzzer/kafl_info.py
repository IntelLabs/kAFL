#!/usr/bin/env python3
#
# Copyright (C) 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright (C) 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

""" 
Execute a kAFL target once, using a special "info" binary as agent.

This is used in cases where we want to automatically extract some information
from a target before proper fuzzing, e.g. the location of kernel modules in a VM
snapshot. Perhaps this feature should be merged into kafl_debug.py.
"""

import os
import sys

import common.color
from common.self_check import self_check
from common.config import InfoConfiguration

KAFL_ROOT = os.path.dirname(os.path.realpath(__file__)) + "/"
KAFL_BANNER = KAFL_ROOT + "banner.txt"
KAFL_CONFIG = KAFL_ROOT + "kafl.ini"

def main():

    with open(KAFL_BANNER) as f:
        for line in f:
            print(line.replace("\n", ""))

    print("<< " + common.color.BOLD + common.color.OKGREEN +
            sys.argv[0] + ": Agent Info Dumper " + common.color.ENDC + ">>\n")

    if not self_check(KAFL_ROOT):
        return 1

    import info.core
    cfg = InfoConfiguration(KAFL_CONFIG)
    return info.core.start(cfg)


if __name__ == "__main__":
    main()
