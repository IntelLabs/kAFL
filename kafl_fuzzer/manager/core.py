# Copyright 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Startup routines for kAFL Fuzzer.

Spawn a Manager and one or more Worker processes, where Manager implements the
global fuzzing queue and scheduler and Workers implement mutation stages and
Qemu/KVM execution.

Prepare the kAFL workdir and copy any provided seeds to be picked up by the scheduler.
"""

import multiprocessing
import time
import sys

from kafl_fuzzer.common.logger import init_logger, logger
from kafl_fuzzer.common.self_check import post_self_check
from kafl_fuzzer.common.util import prepare_working_dir, copy_seed_files, qemu_sweep
from kafl_fuzzer.manager.manager import ManagerTask
from kafl_fuzzer.worker.worker import worker_loader

def graceful_exit(workers):
    for s in workers:
        s.terminate()

    logger.info("Waiting for Workers to shutdown...")
    time.sleep(1)

    while len(workers) > 0:
        for s in workers:
            if s and s.exitcode is None:
                logger.info("Still waiting on %s (pid=%d)..  [hit Ctrl-c to abort..]" % (s.name, s.pid))
                s.join(timeout=1)
            else:
                workers.remove(s)


def start(config):    

    if not post_self_check(config):
        logger.error("Startup checks failed. Exit.")
        return -1
        
    if not prepare_working_dir(config):
        logger.error("Refuse to operate on existing work directory. Use --purge to override.")
        return 1

    work_dir   = config.work_dir
    seed_dir   = config.seed_dir
    num_worker = config.workers

    init_logger(config)

    if seed_dir:
        if not copy_seed_files(work_dir, seed_dir):
            logger.error("Error when importing seeds. Exit.")
            return 1
    else:
        logger.warn("Warning: Launching without -seed_dir?")
        time.sleep(1)

    # Without -ip0, Qemu will not active PT tracing and we turn into a blind fuzzer
    if not config.ip0:
        logger.warn("No PT trace region defined.")

    manager = ManagerTask(config)

    workers = []
    for i in range(num_worker):
        workers.append(multiprocessing.Process(name="Worker " + str(i), target=worker_loader, args=(i,config)))
        workers[i].start()

    try:
        manager.loop()
    except KeyboardInterrupt:
        logger.info("Received Ctrl-C, killing workers...")
    except SystemExit as e:
        logger.info("Manager exit: " + str(e))
    finally:
        graceful_exit(workers)

    time.sleep(1)
    qemu_sweep("Detected potential qemu zombies, try to kill -9:")
    sys.exit(0)
