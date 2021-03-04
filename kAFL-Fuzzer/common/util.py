# Copyright 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

import glob
import os
import shutil
import sys
import tempfile
import string
from shutil import copyfile

from common import color
from common.log import logger

class Singleton(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]

# pretty-printed hexdump
def hexdump(src, length=16):
    hexdump_filter = ''.join([(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])
    lines = []
    for c in range(0, len(src), length):
        chars = src[c:c + length]
        hex_value = ' '.join(["%02x" % ord(x) for x in chars])
        printable = ''.join(["%s" % ((ord(x) <= 127 and hexdump_filter[ord(x)]) or '.') for x in chars])
        lines.append("%04x  %-*s  %s\n" % (c, length * 3, hex_value, printable))
    return ''.join(lines)

# return safely printable portion of binary input data
# use verbatim=True to maintain whitespace/formatting
def strdump(data, verbatim=False):
    dump = data.decode("utf-8", errors='backslashreplace')

    if verbatim:
        dump = ''.join([x if x in string.printable or x in "\b\x1b" else "." for x in dump])
    else:
        dump = ''.join([x if x in string.printable and x not in "\a\b\t\n\r\x0b\x0c" else "." for x in dump])
    return dump

def atomic_write(filename, data):
    # rename() is atomic only on same filesystem so the tempfile must be in same directory
    with tempfile.NamedTemporaryFile(dir=os.path.dirname(filename), delete=False) as f:
        f.write(data)
    os.rename(f.name, filename)

def read_binary_file(filename):
    with open(filename, 'rb') as f:
        return f.read()

def find_diffs(data_a, data_b):
    first_diff = 0
    last_diff = 0
    for i in range(min(len(data_a), len(data_b))):
        if data_a[i] != data_b:
            if first_diff == 0:
                first_diff = i
            last_diff = i
    return first_diff, last_diff

def prepare_working_dir(config):

    work_dir   = config.argument_values["work_dir"]
    purge      = config.argument_values['purge']

    if os.path.exists(work_dir) and not purge:
        return False

    folders = ["/corpus/regular", "/corpus/crash",
               "/corpus/kasan", "/corpus/timeout",
               "/metadata", "/bitmaps", "/imports", "/snapshot"]

    shutil.rmtree(work_dir, ignore_errors=True)

    project_name = work_dir.split("/")[-1]
    for path in glob.glob("/dev/shm/kafl_%s_*" % project_name):
        os.remove(path)

    if os.path.exists("/dev/shm/kafl_tfilter"):
        os.remove("/dev/shm/kafl_tfilter")

    for folder in folders:
        os.makedirs(work_dir + folder)

    open(work_dir + "/page_cache.lock", "wb").close()
    open(work_dir + "/page_cache.dump", "wb").close()
    open(work_dir + "/page_cache.addr", "wb").close()

    if config.argument_values.get('funky', False):
        os.makedirs(work_dir + "/funky/")

    if config.argument_values.get('trace', False):
        os.makedirs(work_dir + "/traces/")

    return True

def copy_seed_files(working_directory, seed_directory):
    if len(os.listdir(seed_directory)) == 0:
        return False

    if len(os.listdir(working_directory)) == 0:
        return False

    i = 0
    for (directory, _, files) in os.walk(seed_directory):
        for f in files:
            path = os.path.join(directory, f)
            if os.path.exists(path):
                try:
                    copyfile(path, working_directory + "/imports/" + "seed_%05d" % i)
                    i += 1
                except PermissionError:
                    logger.error("Skipping seed file %s (permission denied)." % path)
    return True

def print_hprintf(msg):
    sys.stdout.write(color.HPRINTF + msg + color.ENDC)
    sys.stdout.flush()

def is_float(value):
    try:
        float(value)
        return True
    except ValueError:
        return False


def is_int(value):
    try:
        int(value)
        return True
    except ValueError:
        return False

def json_dumper(obj):
    return obj.__dict__
