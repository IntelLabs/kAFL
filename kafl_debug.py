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

from kafl_fuzzer.common.self_check import self_check, post_self_check
from kafl_fuzzer.common.config import ConfigArgsParser
from kafl_fuzzer.common.util import print_banner
from kafl_fuzzer.debug import core

def main():

    print_banner("kAFL Debugger")

    if not self_check():
        return 1

    parser = ConfigArgsParser()
    config = parser.parse_debug_options()

    if not post_self_check(config):
        return -1

    return core.start(config)


if __name__ == "__main__":
    main()
