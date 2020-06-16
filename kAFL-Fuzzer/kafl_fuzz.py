#!/usr/bin/env python3
#
# Copyright (C) 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright (C) 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Launcher for Fuzzing with kAFL. Check fuzzer/core.py for more.
"""

import os
import sys

import common.color
from common.self_check import self_check
from common.config import FuzzerConfiguration

KAFL_ROOT = os.path.dirname(os.path.realpath(__file__)) + "/"
KAFL_BANNER = KAFL_ROOT + "banner.txt"
KAFL_CONFIG = KAFL_ROOT + "kafl.ini"

def main():

    with open(KAFL_BANNER) as f:
        for line in f:
            print(line.replace("\n", ""))

    print("<< " + common.color.BOLD + common.color.OKGREEN +
            sys.argv[0] + ": Kernel Fuzzer " + common.color.ENDC + ">>\n")

    if not self_check(KAFL_ROOT):
        return 1

    import fuzzer.core
    cfg = FuzzerConfiguration(KAFL_CONFIG)
    return fuzzer.core.start(cfg)


if __name__ == "__main__":
    main()
