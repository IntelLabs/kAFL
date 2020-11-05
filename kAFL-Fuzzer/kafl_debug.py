#!/usr/bin/env python3
#
# Copyright (C) 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright (C) 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Execute a given kAFL target with individual test inputs for purpose of debug/inspection.
"""

import os
import sys

import common.color
from common.self_check import self_check
from common.config import DebugConfiguration

KAFL_ROOT = os.path.dirname(os.path.realpath(__file__)) + "/"
KAFL_BANNER = KAFL_ROOT + "banner.txt"
KAFL_CONFIG = KAFL_ROOT + "kafl.ini"

def main():

    with open(KAFL_BANNER) as f:
        for line in f:
            print(line.replace("\n", ""))

    print("<< " + common.color.BOLD + common.color.OKGREEN +
            sys.argv[0] + ": kAFL Debugger " + common.color.ENDC + ">>\n")

    if not self_check(KAFL_ROOT):
        return 1

    import debug.core
    cfg = DebugConfiguration(KAFL_CONFIG)
    return debug.core.start(cfg)


if __name__ == "__main__":
    main()
