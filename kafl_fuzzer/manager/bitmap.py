# Copyright 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
kAFL Fuzzer Bitmap
"""

import array
import ctypes
import inspect
import mmap
import os


class GlobalBitmap:
    bitmap_native_so = ctypes.CDLL(
        os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe()))) + '/native/bitmap.so')
    bitmap_native_so.are_new_bits_present_no_apply_lut.restype = ctypes.c_uint64
    bitmap_native_so.are_new_bits_present_do_apply_lut.restype = ctypes.c_uint64
    bitmap_size = None

    def __init__(self, name, config, bitmap_size, read_only=True):
        assert (not GlobalBitmap.bitmap_size or GlobalBitmap.bitmap_size == bitmap_size)
        GlobalBitmap.bitmap_size = bitmap_size
        self.name = name
        self.config = config
        self.bitmap_size = bitmap_size
        self.create_bitmap(name)
        self.c_bitmap = (ctypes.c_uint8 * self.bitmap_size).from_buffer(self.bitmap)
        self.read_only = read_only
        if not read_only:
            self.flush_bitmap()

    def flush_bitmap(self):
        assert (not self.read_only)
        for i in range(self.bitmap_size):
            self.c_bitmap[i] = 0

    def create_bitmap(self, name):
        self.bitmap_fd = os.open(self.config.argument_values['work_dir'] + "/bitmaps/" + name,
                                 os.O_RDWR | os.O_SYNC | os.O_CREAT)
        os.ftruncate(self.bitmap_fd, self.config.config_values['BITMAP_SHM_SIZE'])
        self.bitmap = mmap.mmap(self.bitmap_fd, self.bitmap_size, mmap.MAP_SHARED, mmap.PROT_WRITE | mmap.PROT_READ)

    def get_new_byte_and_bit_counts(self, local_bitmap):
        c_new_bitmap = local_bitmap.cbuffer
        assert c_new_bitmap
        if local_bitmap.is_lut_applied():
            result = GlobalBitmap.bitmap_native_so.are_new_bits_present_no_apply_lut(self.c_bitmap, c_new_bitmap,
                                                                                     ctypes.c_uint64(self.bitmap_size))
        else:
            result = GlobalBitmap.bitmap_native_so.are_new_bits_present_do_apply_lut(self.c_bitmap, c_new_bitmap,
                                                                                     ctypes.c_uint64(self.bitmap_size))
            local_bitmap.lut_applied = True

        byte_count = result >> 32
        bit_count = result & 0xFFFFFFFF
        return byte_count, bit_count

    def get_new_byte_and_bit_offsets(self, local_bitmap):
        # TODO ensure that local_bitmap doesn't need a copy to increase performance
        # when working on a shared version, ensure that all subsequent tests on the bitmap get a properly bucketized bitmap (Trim, Redqueen etc)...
        byte_count, bit_count = self.get_new_byte_and_bit_counts(local_bitmap)

        c_new_bitmap = local_bitmap.cbuffer
        assert c_new_bitmap

        new_bytes = None
        new_bits = None
        if byte_count != 0 or bit_count != 0:
            new_bytes, new_bits = self.determine_new_bytes(c_new_bitmap)

            # print("byte counts: %d %d %s"%(len(new_bytes), byte_count, repr(new_bytes)))
            # print("bit counts: %d %d %s"%(len(new_bits), bit_count, repr(new_bits)))
            assert (len(new_bytes) == byte_count)
            assert (len(new_bits) == bit_count)

        return new_bytes, new_bits

    @staticmethod
    def apply_lut(exec_result):
        assert not exec_result.is_lut_applied()
        c_new_bitmap = exec_result.cbuffer
        GlobalBitmap.bitmap_native_so.apply_bucket_lut(c_new_bitmap, ctypes.c_uint64(exec_result.bitmap_size))
        exec_result.lut_applied = True

    @staticmethod
    def all_new_bits_still_set(old_bits, new_bitmap):
        assert new_bitmap.is_lut_applied()
        c_new_bitmap = new_bitmap.cbuffer
        return all([c_new_bitmap[index] == byteval for (index, byteval) in old_bits.items()])

    def determine_new_bytes(self, exec_result):
        new_bytes = {}
        new_bits = {}
        assert (len(exec_result) == len(self.c_bitmap))
        for index in range(self.bitmap_size):
            global_byte = self.c_bitmap[index]
            local_byte = exec_result[index]
            if (global_byte | local_byte) != global_byte:
                if global_byte == 0:
                    new_bytes[index] = local_byte
                else:
                    new_bits[index] = local_byte
        return new_bytes, new_bits

    def update_with(self, exec_result):
        assert (not self.read_only)
        GlobalBitmap.bitmap_native_so.update_global_bitmap(self.c_bitmap, exec_result.cbuffer,
                                                           ctypes.c_uint64(self.bitmap_size))


class BitmapStorage:
    def __init__(self, config, bitmap_size, prefix, read_only=True):
        self.prefix = prefix
        self.bitmap_size = bitmap_size
        self.normal_bitmap = GlobalBitmap(prefix + "_normal_bitmap", config, self.bitmap_size, read_only)
        self.crash_bitmap = GlobalBitmap(prefix + "_crash_bitmap", config, self.bitmap_size, read_only)
        self.kasan_bitmap = GlobalBitmap(prefix + "_kasan_bitmap", config, self.bitmap_size, read_only)
        self.timeout_bitmap = GlobalBitmap(prefix + "_timeout_bitmap", config, self.bitmap_size, read_only)

    def get_bitmap_for_node_type(self, exit_reason):
        if exit_reason == "regular":
            return self.normal_bitmap
        elif exit_reason == "timeout":
            return self.timeout_bitmap
        elif exit_reason == "crash":
            return self.crash_bitmap
        elif exit_reason == "kasan":
            return self.kasan_bitmap
        else:
            assert False, "unexpected node type: {}".format(exit_reason)

    def check_storage_logic(self, exec_result, new_bytes, new_bits):
        if exec_result.exit_reason == "regular" and (new_bits or new_bytes):
            return True
        elif new_bytes:
            return True
        return False

    def should_send_to_manager(self, exec_result, exit_reason):
        relevant_bitmap = self.get_bitmap_for_node_type(exit_reason)
        new_bytes, new_bits = relevant_bitmap.get_new_byte_and_bit_counts(exec_result)
        return self.check_storage_logic(exec_result, new_bytes, new_bits)

#    def should_send_to_manager(self, exec_result):
#        relevant_bitmap = self.get_bitmap_for_node_type(exec_result.exit_reason)
#        new_bytes, new_bits = relevant_bitmap.get_new_byte_and_bit_counts(exec_result)
#        return self.check_storage_logic(exec_result, new_bytes, new_bits)

    def should_store_in_queue(self, exec_result):
        relevant_bitmap = self.get_bitmap_for_node_type(exec_result.exit_reason)
        new_bytes, new_bits = relevant_bitmap.get_new_byte_and_bit_offsets(exec_result)
        accepted = self.check_storage_logic(exec_result, new_bytes, new_bits)
        if accepted:
            relevant_bitmap.update_with(exec_result)

        return accepted, new_bytes, new_bits
