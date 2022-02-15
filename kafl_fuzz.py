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

from kafl_fuzzer.common.self_check import self_check
from kafl_fuzzer.common.config import FuzzerConfiguration
from kafl_fuzzer.common.util import print_banner

KAFL_ROOT = os.path.dirname(os.path.realpath(__file__)) + "/kafl_fuzzer/"
KAFL_CONFIG = KAFL_ROOT + "kafl.ini"

def main():

    print_banner("kAFL Fuzzer")

    if not self_check(KAFL_ROOT):
        return 1

    import kafl_fuzzer.manager.core
    cfg = FuzzerConfiguration(KAFL_CONFIG)
    return kafl_fuzzer.manager.core.start(cfg)


if __name__ == "__main__":
    main()
