# Copyright (C) 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright (C) 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Helper functions used by fuzzing inference and mutation algorithms
"""

import ctypes
import fastrand
import inspect
import os
import struct
from ctypes import c_uint8, c_uint16, c_uint32

# TODO Align with kafl.ini payload_shm_size and other instances of payload max size!
KAFL_MAX_FILE = 128 << 10

# TODO: Align havoc stage parameters with AFL or better
HAVOC_BLK_SMALL = 32
HAVOC_BLK_MEDIUM = 128
HAVOC_BLK_LARGE = 1500
HAVOC_BLK_XL = 32768

# TODO: Compare kAFL HAVOC/deterministic round scheduling against AFL
AFL_ARITH_MAX = 35
AFL_HAVOC_MIN = 256
AFL_HAVOC_CYCLES = 5000
AFL_HAVOC_STACK_POW2 = 5

interesting_8_Bit = [-128, -1, 0, 1, 16, 32, 64, 100, 127]
interesting_16_Bit = interesting_8_Bit + [-32768, -129, 128, 255, 256, 512, 1000, 1024, 4096, 32767]
interesting_32_Bit = interesting_16_Bit + [-2147483648, -100663046, -32769, 32768, 65535, 65536, 100663045, 2147483647]


# Todo
def AFL_choose_block_len(limit):
    global HAVOC_BLK_SMALL
    global HAVOC_BLK_MEDIUM
    global HAVOC_BLK_LARGE
    global HAVOC_BLK_XL
    min_value = 1
    max_value = 32

    # u32 rlim = MIN(queue_cycle, 3);
    # if (!run_over10m) rlim = 1;
    rlim = 1
    case = rand.int(rlim)
    if case == 0:
        min_value = 1
        max_value = HAVOC_BLK_SMALL
    elif case == 1:
        min_value = HAVOC_BLK_SMALL
        max_value = HAVOC_BLK_MEDIUM
    else:
        case = rand.int(10)
        if case == 0:
            min_value = HAVOC_BLK_LARGE
            max_value = HAVOC_BLK_XL
        else:
            min_value = HAVOC_BLK_MEDIUM
            max_value = HAVOC_BLK_LARGE

    if min_value >= limit:
        min_value = 1;

    return min_value + rand.int(MIN(max_value, limit) - min_value + 1);


# Todo
def AFL_choose_block_len2(limit):
    min_value = 1
    max_value = 16

    if min_value >= limit:
        min_value = limit

    return min_value + rand.int(MIN(max_value, limit) - min_value + 1)


def MIN(value_a, value_b):
    if value_a > value_b:
        return value_b
    else:
        return value_a


# Wrapper for your favorite RNG solution
import random
class rand:

    def __init__():
        self.reseed()

    def reseed():
        fastrand.pcg32_seed(random.getrandbits(63))
        fastrand.pcg32bounded(2) # flush initial 0 output (?!)

    def bytes(num):
        return bytes([rand.int(256) for _ in range(num)])

    # return integer N := 0 <= n < limit
    # Intended semantics:
    #   if rand.int(100) < 50 # execute with p(0.5)
    #   if rand.int(2)        # execute with p(0.5)
    # a[rand.int(len(a)) = 5  # never out of bounds
    def int(limit):
        if limit == 0:
            return 0
        return fastrand.pcg32bounded(limit)

    def select(arg):
        return arg[rand.int(len(arg))]

    def shuffle(arg):
        return random.shuffle(arg)


def in_range_8(value):
    return ctypes.c_uint8(value).value


def in_range_16(value):
    return ctypes.c_uint16(value).value


def in_range_32(value):
    return ctypes.c_uint32(value).value


def swap_16(value):
    return struct.unpack("<H", struct.pack(">H", value))[0]


def swap_32(value):
    return struct.unpack("<I", struct.pack(">I", value))[0]


bitmap_native_so = None


def load_native():
    global bitmap_native_so
    bitmap_native_so = ctypes.CDLL(
        os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe()))) + '/../native/bitmap.so')


def is_not_bitflip(value):
    global bitmap_native_so
    if bitmap_native_so is None:
        load_native()
    bitmap_native_so.could_be_bitflip.restype = c_uint8
    result = bitmap_native_so.could_be_bitflip(c_uint32(value))

    if result == 0:
        return True
    else:
        return False


def is_not_arithmetic(value, new_value, num_bytes, arith_max=AFL_ARITH_MAX):
    global bitmap_native_so
    if bitmap_native_so is None:
        load_native()
    bitmap_native_so.could_be_arith.restype = c_uint8
    result = bitmap_native_so.could_be_arith(c_uint32(value), c_uint32(new_value),
                                             c_uint8(num_bytes), c_uint8(arith_max))

    if result == 0:
        return True
    else:
        return False


def is_not_interesting(value, new_value, num_bytes, le):
    global bitmap_native_so
    if bitmap_native_so is None:
        load_native()
    bitmap_native_so.could_be_interest.restype = c_uint8
    result = bitmap_native_so.could_be_interest(c_uint32(value), c_uint32(new_value), c_uint8(num_bytes), c_uint8(le))

    if result == 0:
        return True
    else:
        return False
