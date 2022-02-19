# Copyright (C) 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright (C) 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Interface to Radamsa fuzzer (optional havoc stage)
"""

import glob
import math
import os
import random
import subprocess

from kafl_fuzzer.common.logger import logger
from kafl_fuzzer.common.util import read_binary_file
from kafl_fuzzer.technique.helper import KAFL_MAX_FILE


def init_radamsa(config, pid):
    global corpus_dir
    global input_dir
    global radamsa_path

    corpus_dir = config.work_dir + "/corpus/"
    radamsa_path = config.radamsa_path
    input_dir = config.work_dir + "/radamsa_%d/" % pid

    if not os.path.isdir(input_dir):
        os.makedirs(input_dir)

def perform_radamsa_round(data, func, num_inputs):
    global corpus_dir
    global input_dir
    global radamsa_path

    last_n = 10
    rand_n = 40
    files = sorted(glob.glob(corpus_dir + "/regular/payload_*"))
    samples = files[-last_n:] + random.sample(files[:-last_n], max(0, min(rand_n, len(files) - last_n)))

    if not samples:
        return

    radamsa_cmd = [radamsa_path,
            "-T", str(KAFL_MAX_FILE),
            "-o", input_dir + "input_%05n",
            "-n", str(num_inputs)] + samples

    try:
        #logger.debug("Radamsa cmd: " + repr(radamsa_cmd))
        p = subprocess.Popen(radamsa_cmd, stdin=subprocess.PIPE, shell=False)

        while True:
            try:
                # repeatedly wait and process an item to update kAFL stats
                for path in os.listdir(input_dir):
                    #logger.debug("Radamsa input %s" % path)
                    func(read_binary_file(input_dir+path))
                    os.remove(input_dir+path)
                p.communicate(timeout=1)
                break
            except subprocess.SubprocessError as e:
                pass
    except SystemExit:
        # be sure to cleanup on kill signal
        p.terminate()

    # actual processing of generated inputs
    for path in os.listdir(input_dir):
        #logger.debug("Radamsa input %s" % path)
        func(read_binary_file(input_dir+path))
        os.remove(input_dir+path)

def mutate_seq_radamsa_array(data, func, num_inputs):
    # avoid large amounts of temp files in radamsa (use socket I/O option?)
    max_round_inputs = 512
    rounds = math.ceil(num_inputs / max_round_inputs)

    logger.debug("Radamsa: %d inputs in %d rounds.." % (num_inputs, rounds))

    for _ in range(rounds):
        perform_radamsa_round(data, func, min(max_round_inputs, num_inputs))
        num_inputs -= max_round_inputs
