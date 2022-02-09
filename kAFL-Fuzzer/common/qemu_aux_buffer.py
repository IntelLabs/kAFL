# Copyright 2020 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright 2021 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

import mmap
import os
import struct

from common.log import logger
from common.util import strdump
from collections import namedtuple
from enum import IntEnum


result_tuple = namedtuple('result_tuple', [
    'state',
    'exec_done',
    'exec_code',
    'reloaded',

    'pt_overflow',
    'page_fault',
    'tmp_snap',
    'pad3',

    'page_fault_addr',
    'dirty_pages',
    'pt_trace_size',
    'bb_cov',
    'runtime_usec',
    'runtime_sec',
    ])

my_magic = 0x54502d554d4551
my_version = 0x3
my_hash = 0x54

HEADER_SIZE = 128
CAP_SIZE = 256
CONFIG_SIZE = 512
STATUS_SIZE = 512
MISC_SIZE = 4096-(HEADER_SIZE+CAP_SIZE+CONFIG_SIZE+STATUS_SIZE)

HEADER_OFFSET = 0
CAP_OFFSET = HEADER_SIZE
CONFIG_OFFSET = CAP_OFFSET + CAP_SIZE
STATUS_OFFSET = CONFIG_OFFSET + CONFIG_SIZE
MISC_OFFSET = STATUS_OFFSET + STATUS_SIZE

class QemuAuxRC(IntEnum):
    SUCCESS = 0
    CRASH = 1
    HPRINTF = 2
    TIMEOUT = 3
    INPUT_BUF_WRITE = 4
    ABORT = 5
    SANITIZER = 6

class QemuAuxBuffer:

    def __init__(self, file):
        self.aux_buffer_fd = os.open(file, os.O_RDWR | os.O_SYNC)
        self.aux_buffer = mmap.mmap(self.aux_buffer_fd, 0x1000, mmap.MAP_SHARED, mmap.PROT_WRITE | mmap.PROT_READ) # fix this later
        self.current_timeout = None

    def validate_header(self):
        qemu_magic = (struct.unpack('L', self.aux_buffer[0:8])[0])
        qemu_version = (struct.unpack('H', self.aux_buffer[8:10])[0])
        qemu_hash = (struct.unpack('H', self.aux_buffer[10:12])[0])

        if qemu_magic != my_magic:
            logger.error("Magic mismatch: %x != %x" % (qemu_magic, my_magic))
            return False

        if qemu_version != my_version:
            logger.error("Version mismatch: %x != %x" % (qemu_version, my_version))
            return False 

        if qemu_hash != my_hash:
            logger.error("Hash mismatch: %x != %x" % (qemu_hash, my_hash))
            return False

        return True

    def get_misc_buf(self):
        mlen = struct.unpack('H', self.aux_buffer[MISC_OFFSET+0:MISC_OFFSET+2])[0]
        return self.aux_buffer[MISC_OFFSET+2:MISC_OFFSET+2+mlen]

    def get_state(self):
        return struct.unpack_from('B', self.aux_buffer, offset=STATUS_OFFSET)[0]

    def get_result(self):
        return result_tuple._make(
                struct.unpack_from('B?B? ???? QIIIII',
                                   self.aux_buffer,
                                   offset=STATUS_OFFSET))

    def set_config_buffer_changed(self):
        self.aux_buffer[CONFIG_OFFSET+0] = 1

    def set_timeout(self, timeout):
        assert(isinstance(timeout, (int, float)))
        self.current_timeout = timeout
        secs = int(timeout)
        usec = int(1000*1000*(timeout - secs))
        struct.pack_into("=BI", self.aux_buffer, CONFIG_OFFSET+1, secs, usec)
        self.set_config_buffer_changed()

    def get_timeout(self):
        return self.current_timeout

    def set_redqueen_mode(self, enable):
        self.aux_buffer[CONFIG_OFFSET+6] = int(enable)
        self.set_config_buffer_changed()

    def set_trace_mode(self, enable):
        self.aux_buffer[CONFIG_OFFSET+7] = int(enable)
        self.set_config_buffer_changed()

    def set_reload_mode(self, enable):
        self.aux_buffer[CONFIG_OFFSET+8] = int(enable)
        self.set_config_buffer_changed()

    def dump_page(self, addr):
        struct.pack_into("BQ", self.aux_buffer, CONFIG_OFFSET+10, 1, addr)
        self.set_config_buffer_changed()
