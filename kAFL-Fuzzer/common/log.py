# Copyright 2021 Armand Schinkel
#
# SPDX-License-Identifier: AGPL-3.0-or-later

#import codecs
import os
import sys
import time

from datetime import timedelta

import common.color as color

LOG_LEVEL = {
    "DEBUG": 1, # verbose/debug - enable with --debug
    "INFO":  2, # normal reporting - disable stdout with --quiet but --logging will still include them
    "WARN":  3, # minor/correctable issues
    "ERROR": 4, # major/fatal issues
}

# --quiet - mute stdout, disabling debug, info and statistics output
# --verbose - enable verbose stdout (logger.debug())
# --debug - enable extra debug checks and qemu tracing
# --log - log outputs to file, combine with --debug for max verbosity
# --hprintf_log - write hprintf to separate files

logger = None

class Logger():
    def __init__(self):
        self.init_time = time.time()
        self.init()
        self.stdout_level = LOG_LEVEL["INFO"]
        self.file_level = None
        self.log_file = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if self.log_file:
            self.log_file.close()
        return

    def init(self, stdout_level="INFO", file_level=None, log_file="/debug.log"):
        self.stdout_level = LOG_LEVEL[stdout_level]
        if file_level:
            self.file_level = LOG_LEVEL[file_level]
            self.log_file = open(self.work_dir + log_file, "w+")

    def file_log(self, msg_level, msg):
        if self.file_level and self.file_level <= LOG_LEVEL[msg_level]:
            self.log_file.write(str(timedelta(seconds=time.time() - self.init_time)) + " " + msg + "\n")
            self.log_file.flush()
 
    def debug(self, msg):
        self.file_log("DEBUG", msg)
        if self.stdout_level <= LOG_LEVEL["DEBUG"]:
            print(color.FLUSH_LINE + msg)

    def info(self, msg):
        self.file_log("INFO", msg)
        if self.stdout_level <= LOG_LEVEL["INFO"]:
            print(color.FLUSH_LINE + msg)

    def warn(self, msg):
        self.file_log("WARN", "[WARN] " + msg)
        print(color.FLUSH_LINE + color.WARNING + msg + color.ENDC, file=sys.stderr, flush=True)

    def error(self, msg):
        self.file_log("ERROR", "[ERROR] " + msg)
        print(color.FLUSH_LINE + color.FAIL + "[ERROR] " + msg + color.ENDC, file=sys.stderr, flush=True)

logger = Logger()

def init_logger(config):
    global logger

    # Default is INFO level to console, and no file logging.
    # Useful modifiers:
    #  -v / -q to increase/decrease console logging
    #  -l / --log to enable file logging at standard level
    #  --debug to enable extra debug checks, qemu tracing, etc (slow!)
    #
    # We allow some sensible combinations, e.g. --quiet --log [--debug]
    if config.argument_values["quiet"]:
        stdout_level = "WARN"
    elif config.argument_values["verbose"] or config.argument_values["debug"]:
        stdout_level = "DEBUG"
    else:
        stdout_level = "INFO"

    if config.argument_values["log"]:
        if config.argument_values["debug"]:
            file_level = "DEBUG"
        else:
            file_level = "INFO"
    else:
        file_level = None

    logger.work_dir = config.argument_values["work_dir"]
    logger.init(stdout_level, file_level)
