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
from kafl_fuzzer.common.config import ConfigArgsParser
from kafl_fuzzer.common.util import print_banner

from kafl_fuzzer.manager import core as fuzzer

def main():

    print_banner("kAFL Fuzzer")

    if not self_check():
        return 1

    parser = ConfigArgsParser()
    config = parser.parse_fuzz_options()

    return fuzzer.start(config)


if __name__ == "__main__":
    main()
