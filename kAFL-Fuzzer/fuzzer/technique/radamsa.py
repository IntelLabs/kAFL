# Copyright (C) 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright (C) 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Interface to Radamsa fuzzer (optional havoc stage)
"""

import glob
import os
import random
import math
import subprocess

from common.config import FuzzerConfiguration
from common.debug import log_radamsa
from common.util import read_binary_file


def init_radamsa(config, slave_id):
    global corpus_dir
    global input_dir
    global radamsa_path

    corpus_dir = config.argument_values['work_dir'] + "/corpus/"
    radamsa_path = config.config_values["RADAMSA_LOCATION"]
    input_dir = config.argument_values['work_dir'] + "/radamsa_%d/" % slave_id

    if not os.path.isdir(input_dir):
        os.makedirs(input_dir)

def perform_radamsa_round(data, func, num_inputs):
    global corpus_dir
    global input_dir
    global radamsa_path

    last_n = 5
    rand_n = 10
    files = sorted(glob.glob(corpus_dir + "/regular/payload_*"))
    samples = files[-last_n:] + random.sample(files[:-last_n], max(0, min(rand_n, len(files) - last_n)))

    if not samples:
        return

    radamsa_cmd = [radamsa_path,
            "-o", input_dir + "input_%05n",
            "-n", str(num_inputs)] + samples

    #log_radamsa("Radamsa cmd: " + repr(radamsa_cmd))
    p = subprocess.Popen(radamsa_cmd, stdin=subprocess.PIPE, shell=False)

    try:
        p.communicate(timeout=10)
    except subprocess.SubprocessError as e:
        log_radamsa("Radamsa exception %s" % str(e))
        p.kill()
        p.communicate()

    for path in os.listdir(input_dir):
        #log_radamsa("Radamsa input %s" % path)
        func(read_binary_file(input_dir+path))
        os.remove(input_dir+path)

def mutate_seq_radamsa_array(data, func, num_inputs):
    # avoid large amounts of temp files in radamsa (use socket I/O option?)
    max_round_inputs = 512
    rounds = math.ceil(num_inputs / max_round_inputs)

    log_radamsa("Radamsa: %d inputs in %d rounds.." % (num_inputs, rounds))

    for _ in range(rounds):
        perform_radamsa_round(data, func, min(max_round_inputs, num_inputs))
        num_inputs -= max_round_inputs
