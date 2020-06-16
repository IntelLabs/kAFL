#!/usr/bin/env python3
#
# Copyright (C) 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright (C) 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Validate Redqueen Input-to-State mutations
"""

import array
import sys

from fuzzer.technique.redqueen import parser
from fuzzer.technique.redqueen.mod import RedqueenInfoGatherer

info = RedqueenInfoGatherer()

info.collected_infos_path = sys.argv[1]
info.num_alternative_inputs = 2

info.get_proposals()
print("got %d mutations on %s" % (info.get_num_mutations(), sys.argv[1]))

orig_input = open(sys.argv[1] + "/input_2.bin", "rb").read()
print("Mutating : %s" % repr(orig_input))


def fake_execute(str, a, b):
    print("executing %s" % repr(str))


info.verbose = True
default_info = {}
info.run_mutate_redqueen(array.array("B", orig_input), fake_execute, default_info)
