# Copyright 2020 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright 2021 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

import mmap
import os
import struct
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

    def print_hprintf_buffer(self):
        hprintf = struct.unpack('?', self.aux_buffer[STATUS_OFFSET+10:STATUS_OFFSET+11])[0]
        if not hprintf:
            return

        len = struct.unpack('H', self.aux_buffer[MISC_OFFSET+0:MISC_OFFSET+2])[0]
        print('\033[0;33m' + str(self.aux_buffer[MISC_OFFSET+2:MISC_OFFSET+2+len]) + '\033[0m')


    def get_status(self):
        state     = struct.unpack('B', self.aux_buffer[STATUS_OFFSET+0:STATUS_OFFSET+1])[0]
        hprintf   = (struct.unpack('?', self.aux_buffer[STATUS_OFFSET+10:STATUS_OFFSET+11])[0])
        exec_done = (struct.unpack('?', self.aux_buffer[STATUS_OFFSET+11:STATUS_OFFSET+12])[0])

        print("STATE: " + str(state) + "\tHPRINTF: " + str(hprintf) + "\tEXEC_DONE: " + str(exec_done))

        if hprintf:
            self.print_hprintf_buffer()

        return state, exec_done

    def get_state(self):
        return struct.unpack_from('B', self.aux_buffer, offset=STATUS_OFFSET)[0]

    def get_result(self):

        status = result_tuple._make(
                struct.unpack_from('B?BBIBB ?? ?? ?? ?? ?? IQII?', self.aux_buffer, offset=STATUS_OFFSET))

        #from pprint import pprint
        #pprint(status)

        self.print_hprintf_buffer()

        self.result["crash_found"] = status.crash_found
        self.result["asan_found"] = status.asan_found
        self.result["timeout_found"] = status.timeout_found
        self.result["reloaded"] = status.reloaded
        self.result["pt_overflow"] = status.pt_overflow
        self.result["page_not_found"] = status.page_fault
        self.result["page_fault_addr"] = status.page_fault_addr
        self.result["success"] = status.success
        self.result["payload_write_fault"] = status.payload_corrupted

        #print("bb_cov: %d" % status.bb_cov)
        return self.result

    def set_config_buffer_changed(self):
        self.aux_buffer[CONFIG_OFFSET+0] = 1

    def set_timeout(self, sec, usec):
        data = struct.pack("=BI", sec, usec)
        self.aux_buffer.seek(CONFIG_OFFSET+1)
        self.aux_buffer.write(data)
        self.aux_buffer.seek(0)
        self.set_config_buffer_changed()

    def enable_redqueen(self):
        self.aux_buffer[CONFIG_OFFSET+6] = 1
        self.set_config_buffer_changed()

    def disable_redqueen(self):
        self.aux_buffer[CONFIG_OFFSET+6] = 0
        self.set_config_buffer_changed()

    def set_trace_mode(self, enable):
        self.aux_buffer[CONFIG_OFFSET+7] = int(enable)
        self.set_config_buffer_changed()

    def set_reload_mode(self, enable):
        self.aux_buffer[CONFIG_OFFSET+8] = int(enable)
        self.set_config_buffer_changed()

    def dump_page(self, addr):
        self.aux_buffer[CONFIG_OFFSET+10] = 1
        data = struct.pack("Q", addr)
        self.aux_buffer.seek(CONFIG_OFFSET+11)
        self.aux_buffer.write(data)
        self.aux_buffer.seek(0)
        self.set_config_buffer_changed()
