# Copyright 2020 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright 2021 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

import mmap
import os
import struct
from common.util import strdump, print_hprintf
from collections import namedtuple

result_tuple = namedtuple('result_tuple', [
    'state',
    'tmp_snap',

    'pad1',
    'pad2',

    'bb_cov',

    'pad3',
    'pad4',

    'hprintf',
    'exec_done',

    'crash_found',
    'asan_found',

    'timeout_found',
    'reloaded',

    'pt_overflow',
    'runtime_sec',

    'page_fault',
    'success',

    'runtime_usec',
    'page_fault_addr',
    'dirty_pages',
    'pt_trace_size',

    'payload_corrupted',
    ])

my_magic = 0x54502d554d4551
my_version = 0x1
my_hash = 0x51

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

class qemu_aux_buffer:

    result = {}

    def __init__(self, file):
        self.aux_buffer_fd = os.open(file, os.O_RDWR | os.O_SYNC)
        self.aux_buffer = mmap.mmap(self.aux_buffer_fd, 0x1000, mmap.MAP_SHARED, mmap.PROT_WRITE | mmap.PROT_READ) # fix this later

    def validate_header(self):
        magic = (struct.unpack('L', self.aux_buffer[0:8])[0])
        version = (struct.unpack('H', self.aux_buffer[8:10])[0])
        hash = (struct.unpack('H', self.aux_buffer[10:12])[0])

        if magic != my_magic:
            print("MAGIC MISMATCH: %x != %x\n" % (magic, my_magic))
            return False

        if version != my_version:
            print("VERSION MISMATCH: %x != %x\n" % (version, my_version))
            return False 

        if hash != my_hash:
            print("HASH MISMATCH: %x != %x\n" % (hash, my_hash))
            return False

        return True

    def get_misc_buf(self):
        mlen = struct.unpack('H', self.aux_buffer[MISC_OFFSET+0:MISC_OFFSET+2])[0]
        return self.aux_buffer[MISC_OFFSET+2:MISC_OFFSET+2+mlen]

    def print_hprintf_buffer(self):
        buf = self.get_misc_buf()
        print_hprintf(strdump(buf[:-1], verbatim=True))

    def get_state(self):
        return struct.unpack_from('B', self.aux_buffer, offset=STATUS_OFFSET)[0]

    def get_result(self):

        status = result_tuple._make(
                struct.unpack_from('B?BBIBB ?? ?? ?? ?B ?? IQII?', self.aux_buffer, offset=STATUS_OFFSET))

        #from pprint import pprint
        #pprint(status._asdict())
        #print("bb_cov: %d" % status.bb_cov)

        if status.hprintf:
            self.print_hprintf_buffer()
        
        return status

    def set_config_buffer_changed(self):
        self.aux_buffer[CONFIG_OFFSET+0] = 1

    def set_timeout(self, timeout):
        secs = int(timeout)
        usec = int(1000*(timeout - secs))
        data = struct.pack("=BI", secs, usec)
        self.aux_buffer.seek(CONFIG_OFFSET+1)
        self.aux_buffer.write(data)
        self.aux_buffer.seek(0)
        self.set_config_buffer_changed()

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
        #self.aux_buffer[CONFIG_OFFSET+10] = 1
        #data = struct.pack("Q", addr)
        #self.aux_buffer.seek(CONFIG_OFFSET+11)
        #self.aux_buffer.write(data)
        #self.aux_buffer.seek(0)
        self.set_config_buffer_changed()
