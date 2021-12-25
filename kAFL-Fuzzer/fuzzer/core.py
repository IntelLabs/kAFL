# Copyright 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Startup routines for kAFL Fuzzer.

Spawn a Master and one or more Slave processes, where Master implements the
global fuzzing queue and scheduler and Slaves implement mutation stages and
Qemu/KVM execution.

Prepare the kAFL workdir and copy any provided seeds to be picked up by the scheduler.
"""

import multiprocessing
import time
import sys

from common.log import init_logger, logger
from common.self_check import post_self_check
from common.util import prepare_working_dir, copy_seed_files, qemu_sweep
from fuzzer.process.master import MasterProcess
from fuzzer.process.slave import slave_loader

def graceful_exit(slaves):
    for s in slaves:
        s.terminate()

    logger.info("Waiting for Slave instances to shutdown...")
    time.sleep(1)

    while len(slaves) > 0:
        for s in slaves:
            if s and s.exitcode is None:
                logger.info("Still waiting on %s (pid=%d)..  [hit Ctrl-c to abort..]" % (s.name, s.pid))
                s.join(timeout=1)
            else:
                slaves.remove(s)


def start(config):    

    if not post_self_check(config):
        #print(FAIL + ERROR_PREFIX + "Startup checks failed. Abort." + ENDC)
        logger.error("Startup checks failed. Exit.")
        return -1
        
    if not prepare_working_dir(config):
        #print(FAIL + ERROR_PREFIX + "Refuse to operate on existing work directory. Use --purge to override." + ENDC)
        logger.error("Refuse to operate on existing work directory. Use --purge to override.")
        return 1

    work_dir   = config.argument_values["work_dir"]
    seed_dir   = config.argument_values["seed_dir"]
    num_slaves = config.argument_values['p']

    init_logger(config)

    if seed_dir:
        if not copy_seed_files(work_dir, seed_dir):
            logger.error("Error when importing seeds. Exit.")
            return 1
    else:
        logger.warn("Warning: Launching without -seed_dir?")
        time.sleep(1)

    # Without -ip0, Qemu will not active PT tracing and we turn into a blind fuzzer
    if not config.argument_values['ip0']:
        logger.warn("No trace region configured! PT feedback disabled!")

    master = MasterProcess(config)

    slaves = []
    for i in range(num_slaves):
        slaves.append(multiprocessing.Process(name="Slave " + str(i), target=slave_loader, args=(i,)))
        slaves[i].start()

    try:
        master.loop()
    except KeyboardInterrupt:
        logger.info("Received Ctrl-C, killing slaves...")
    except SystemExit as e:
        logger.error("Master exit: " + str(e))
    finally:
        graceful_exit(slaves)

    time.sleep(1)
    qemu_sweep("Detected potential qemu zombies, please kill -9:")
    sys.exit(0)
