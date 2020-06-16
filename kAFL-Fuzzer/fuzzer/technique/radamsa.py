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
import socket
import subprocess
import time

from common.config import FuzzerConfiguration
from common.debug import log_radamsa
from common.util import print_fail


def execute(cmd):
    log_radamsa("Radamsa cmd: " + str(cmd))
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=None)
    except:
        # Radamsa stage is experimental and does not seem very effective.
        # Need binary in current/same path as this python file.
        print_fail("Failed to launch radamsa. Do we have the binary in place?")
        raise
    return proc

def init_radamsa(config, slave_id):
    global location_corpus
    global radamsa_cmd
    global radamsa_port

    radamsa_port = 21337 + slave_id
    radamsa_cmd = [
            config.config_values["RADAMSA_LOCATION"],
            "-o", ":%d" % radamsa_port,
            "-n", "inf"]
    location_corpus = config.argument_values['work_dir'] + "/corpus/"

def mutate_seq_radamsa_array(data, func, max_iterations):
    global location_corpus
    global radamsa_cmd
    global radamsa_port

    log_radamsa("Radamsa amount: %d" % max_iterations)
    files = sorted(glob.glob(location_corpus + "/*/payload_*"))
    last_n = 5
    rand_n = 5
    samples = files[-last_n:] + random.sample(files[:-last_n], max(0, min(rand_n, len(files) - last_n)))

    if not samples:
        return

    proc = execute(radamsa_cmd + samples)

    try:
        while True:
            try:
                s = socket.create_connection(("127.0.0.1", radamsa_port), timeout=1)
                s.recv(1)
                break
            except Exception as e:
                log_radamsa("Exception: " + str(e))
                time.sleep(0.1)
            finally:
                try:
                    s.close()
                except:
                    pass

        for i in range(max_iterations):
            try:
                s = socket.create_connection(("127.0.0.1", radamsa_port))
                payload = s.recv(65530)
                s.close()
                size = len(payload)

                if size > (64 << 10):
                    payload = payload[:(2 << 10)]
                if size == 0:
                    func(data)
                else:
                    func(payload)
            except Exception as e:
                log_radamsa("Exception: " + str(e))
                time.sleep(0.1)
            finally:
                try:
                    s.close()
                except:
                    pass

    except Exception as e:
        log_radamsa("Exception: " + str(e))
        raise e
    finally:
        proc.terminate()
        if proc.returncode is None:
            try:
                proc.kill()
            except:
                pass
