"""
Copyright (C) 2019  Sergej Schumilo, Cornelius Aschermann, Tim Blazytko

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

import ctypes
import fastrand
import inspect
import os
import random
import struct
from ctypes import *

KAFL_MAX_FILE = 1 << 15

HAVOC_BLK_SMALL = 32
HAVOC_BLK_MEDIUM = 128
HAVOC_BLK_LARGE = 1500
HAVOC_BLK_XL = 32768

AFL_ARITH_MAX = 35
AFL_HAVOC_MIN = 500
AFL_HAVOC_CYCLES = 5000
AFL_HAVOC_STACK_POW2 = 7

interesting_8_Bit = [-128, -1, 0, 1, 16, 32, 64, 100, 127]
interesting_16_Bit = interesting_8_Bit + [-32768, -129, 128, 255, 256, 512, 1000, 1024, 4096, 32767]
interesting_32_Bit = interesting_16_Bit + [-2147483648, -100663046, -32769, 32768, 65535, 65536, 100663045, 2147483647]

random.seed(os.urandom(4))


def random_string():
    baselen = 4 << RAND(8)
    strlen = (RAND(3) + 1) * baselen + RAND(1) * RAND(baselen)
    return "".join([chr(RAND(256)) for x in xrange(strlen)])


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
    case = RAND(rlim)
    if case == 0:
        min_value = 1
        max_value = HAVOC_BLK_SMALL
    elif case == 1:
        min_value = HAVOC_BLK_SMALL
        max_value = HAVOC_BLK_MEDIUM
    else:
        case = RAND(10)
        if case == 0:
            min_value = HAVOC_BLK_LARGE
            max_value = HAVOC_BLK_XL
        else:
            min_value = HAVOC_BLK_MEDIUM
            max_value = HAVOC_BLK_LARGE

    if min_value >= limit:
        min_value = 1;

    return min_value + RAND(MIN(max_value, limit) - min_value + 1);


# Todo
def AFL_choose_block_len2(limit):
    min_value = 1
    max_value = 16

    if min_value >= limit:
        min_value = limit

    return min_value + RAND(MIN(max_value, limit) - min_value + 1)


def MIN(value_a, value_b):
    if value_a > value_b:
        return value_b
    else:
        return value_a


def reseed():
    random.seed(os.urandom(4))


def RAND(value):
    if value == 0:
        return value
    return fastrand.pcg32bounded(value)


def load_8(value, pos):
    return value[pos]


def load_16(value, pos):
    return (value[pos + 1] << 8) + value[pos + 0]


def load_32(value, pos):
    return (value[pos + 3] << 24) + (value[pos + 2] << 16) + (value[pos + 1] << 8) + value[pos + 0]


def store_8(data, pos, value):
    data[pos] = in_range_8(value)


def store_16(data, pos, value):
    value = in_range_16(value)
    data[pos + 1] = (value & 0xff00) >> 8
    data[pos] = (value & 0x00ff)


def store_32(data, pos, value):
    value = in_range_32(value)
    data[pos + 3] = (value & 0xff000000) >> 24
    data[pos + 2] = (value & 0x00ff0000) >> 16
    data[pos + 1] = (value & 0x0000ff00) >> 8
    data[pos + 0] = (value & 0x000000ff)


def in_range_8(value):
    return ctypes.c_uint8(value).value


def in_range_16(value):
    return ctypes.c_uint16(value).value


def in_range_32(value):
    return ctypes.c_uint32(value).value


def swap_16(value):
    res = in_range_16((((value & 0xff00) >> 8) + ((value & 0xff) << 8)))
    return res


def swap_32(value):
    return ((value & 0x000000ff) << 24) + \
           ((value & 0x0000ff00) << 8) + \
           ((value & 0x00ff0000) >> 8) + \
           ((value & 0xff000000) >> 24)


def to_string_8(value):
    res1 = struct.pack("<B", value)
    return res1


def to_string_16(value):
    res1 = struct.pack("<H", value)
    return res1


def to_string_32(value):
    res1 = struct.pack("<I", value)
    return res1


bitmap_native_so = None


def load_nativ():
    global bitmap_native_so
    bitmap_native_so = CDLL(
        os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe()))) + '/../native/bitmap.so')


def is_not_bitflip(value):
    global bitmap_native_so
    if bitmap_native_so is None:
        load_nativ()
    bitmap_native_so.could_be_bitflip.restype = c_uint8
    result = bitmap_native_so.could_be_bitflip(c_uint32(value))

    if result == 0:
        return True
    else:
        return False


def is_not_arithmetic(value, new_value, num_bytes, set_arith_max=AFL_ARITH_MAX):
    global bitmap_native_so
    if bitmap_native_so is None:
        load_nativ()
    bitmap_native_so.could_be_arith.restype = c_uint8
    result = bitmap_native_so.could_be_arith(c_uint32(value), c_uint32(new_value), c_uint8(num_bytes),
                                             c_uint8(set_arith_max))

    if result == 0:
        return True
    else:
        return False


def is_not_interesting(value, new_value, num_bytes, le):
    global bitmap_native_so
    if bitmap_native_so is None:
        load_nativ()
    bitmap_native_so.could_be_interest.restype = c_uint8
    result = bitmap_native_so.could_be_interest(c_uint32(value), c_uint32(new_value), c_uint8(num_bytes), c_uint8(le))

    if result == 0:
        return True
    else:
        return False
