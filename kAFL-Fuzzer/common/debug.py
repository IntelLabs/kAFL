# Copyright 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

import collections
import sys
import time
from datetime import timedelta
from common.util import strdump

logging_is_enabled = False
debug_file_path = None
output_file = None
init_time = 0.0

def __init_logger():
    global output_file, init_time, debug_file_path
    init_time = time.time()
    output_file = open(debug_file_path, 'w')


def logger(msg):
    global logging_is_enabled, output_file, init_time, shared_list

    if logging_is_enabled:
        if not output_file:
            __init_logger()
        output_file.write("[" + str(timedelta(seconds=time.time() - init_time)) + "] " + msg + "\n")
        output_file.flush()


def enable_logging(workdir):
    global logging_is_enabled, debug_file_path
    logging_is_enabled = True
    debug_file_path = workdir + "/debug.log"


def log_master(msg):
    logger("[MASTR]\t" + msg)


def log_mapserver(msg):
    logger("[MPSRV]\t" + msg)


def log_update(msg):
    logger("[UPDAT]\t" + msg)


def log_slave(msg, qid):
    logger("[SLAVE " + str(qid) + "]\t" + msg)


def log_tree(msg):
    logger("[TREE] \t" + msg)


def log_eval(msg):
    logger("[EVAL] \t" + msg)


def log_redq(msg):
    logger("[RedQ] \t" + msg)


def log_grimoire(msg):
    logger("[GRIM] \t" + msg)


def log_radamsa(msg):
    logger("[RDMA] \t" + msg)


def log_qemu(msg, qid):
    logger("[QEMU " + str(qid) + "]\t" + msg)


def log_core(msg):
    logger("[CORE] \t" + msg)


def log_info(msg):
    logger("[INFO] \t" + msg)

def log_debug(msg):
    logger("[DEBUG]\t" + msg)
