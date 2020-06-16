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
from array import array

from fuzzer.technique.helper import *

__author__ = 'sergej'


def arithmetic_range(data, skip_null=False, effector_map=None, set_arith_max=None):
    if len(data) == 0:
        return 0

    if not set_arith_max:
        set_arith_max = AFL_ARITH_MAX

    data_len = len(data)
    num = 0

    if effector_map:
        byte_count = 0
        for i in range(len(data)):
            if effector_map[i]:
                byte_count += 1
                num += (set_arith_max * 2)
                if byte_count >= 2:
                    num += ((set_arith_max - 2) * 4)
                if byte_count >= 4:
                    num += ((set_arith_max - 2) * 4)

            else:
                byte_count = 0
    else:
        num += (data_len * (set_arith_max * 2))

        if data_len > 1:
            num += ((data_len - 1) * ((set_arith_max - 2) * 4))
        if data_len > 2:
            num += ((data_len - 3) * ((set_arith_max - 2) * 4))

    return num


def mutate_seq_8_bit_arithmetic_array(data, func, default_info, skip_null=False, effector_map=None, set_arith_max=None):
    if not set_arith_max:
        set_arith_max = AFL_ARITH_MAX

    for i in range(0, len(data)):
        if effector_map:
            if not effector_map[i]:
                continue
        if skip_null and data[i] == 0x00:
            continue

        for j in range(1, set_arith_max + 1):
            r = data[i] ^ (data[i] + j)
            if is_not_bitflip(ctypes.c_uint8(r).value):
                data[i] = (data[i] + j) & 0xff
                func(data.tostring(), default_info)
                data[i] = (data[i] - j) & 0xff

            r = data[i] ^ (data[i] - j)
            if is_not_bitflip(ctypes.c_uint8(r).value):
                data[i] = (data[i] - j) & 0xff
                func(data.tostring(), default_info)
                data[i] = (data[i] + j) & 0xff


def mutate_seq_16_bit_arithmetic_array(data, func, default_info, skip_null=False, effector_map=None,
                                       set_arith_max=None):
    if not set_arith_max:
        set_arith_max = AFL_ARITH_MAX

    for i in range(0, len(data) - 1):
        # log_master("orig: %s"%repr(data[i:i+2]))
        # log_master("string: %s"%repr(data[i:i+2].tostring()))
        value = array('H', (data[i:i + 2]).tostring())
        # log_master("array: %s"%repr(value))
        value = in_range_16(value[0])
        # log_master("in range: %s"%repr(value))
        if effector_map:
            if not (effector_map[i] or effector_map[i + 1]):
                continue
        if skip_null and value == 0x00:
            continue
        for j in range(1, set_arith_max + 1):

            # log_master("perform arith 16 on %d %d value: %x +j %x  -j %x"%(i,j,value, value+j, value-j))
            r1 = (value ^ in_range_16(value + j))
            r2 = (value ^ in_range_16(value - j))
            r3 = value ^ swap_16(swap_16(value) + j)
            r4 = value ^ swap_16(swap_16(value) - j)

            # little endian increment
            if is_not_bitflip(r1) and ((value & 0xff) + j) > 0xff:
                # log_master("perform little endian %d +%d = %d"%(i,j, in_range_16(value + j)));
                func(data[:i].tostring() + to_string_16(in_range_16(value + j)) + data[i + 2:].tostring(), default_info)

            # little endian decrement
            if is_not_bitflip(r2) and (value & 0xff) < j:
                # log_master("perform little endian %d -%d = %d"%(i,j, in_range_16(value - j)));
                func(data[:i].tostring() + to_string_16(in_range_16(value - j)) + data[i + 2:].tostring(), default_info)

            # if swap_16(in_range_16(value + j)) == in_range_16(value + j) or swap_16(in_range_16(value - j)) == in_range_16(value - j):
            #    continue

            # big endian increment
            if is_not_bitflip(r3) and ((value >> 8) + j) > 0xff:
                # log_master("perform big endian %d +%d = %d"%(i,j, swap_16(in_range_16(swap_16(value) + j))));
                func(data[:i].tostring() + to_string_16(swap_16(in_range_16(swap_16(value) + j))) + data[
                                                                                                    i + 2:].tostring(),
                     default_info)

            # big endian decrement
            if is_not_bitflip(r4) and (value >> 8) < j:
                # log_master("perform big endian %d -%d = %d"%(i,j, swap_16(in_range_16(swap_16(value) - j))));
                func(data[:i].tostring() + to_string_16(swap_16(in_range_16(swap_16(value) - j))) + data[
                                                                                                    i + 2:].tostring(),
                     default_info)


def mutate_seq_32_bit_arithmetic_array(data, func, default_info, skip_null=False, effector_map=None,
                                       set_arith_max=None):
    if not set_arith_max:
        set_arith_max = AFL_ARITH_MAX

    for i in range(0, len(data) - 3):
        value = array('I', (data[i:i + 4]).tostring())
        value = in_range_32(value[0])

        if effector_map:
            if not (effector_map[i] or effector_map[i + 1] or effector_map[i + 2] or effector_map[i + 3]):
                # log_master("eff skip %d"%i);
                continue

        if skip_null and value == 0x00:
            continue
        for j in range(1, set_arith_max + 1):

            r1 = (value ^ in_range_32(value + j))
            r2 = (value ^ in_range_32(value - j))
            r3 = value ^ swap_32(swap_32(value) + j)
            r4 = value ^ swap_32(swap_32(value) - j)

            # log_master("perform arith 32 on %d %d rs: %d %d %d %d"%(i,j, r1,r2,r3,r4));
            # little endian increment
            if is_not_bitflip(r1) and in_range_32((value & 0xffff) + j) > 0xffff:
                # log_master("perform little endian %d -%d = %d"%(i,j, in_range_32(value + j)));
                func(data[:i].tostring() + to_string_32(in_range_32(value + j)) + data[i + 4:].tostring(), default_info)

            # little endian decrement
            if is_not_bitflip(r2) and in_range_32(value & 0xffff) < j:
                # log_master("perform little endian %d -%d = %d"%(i,j, in_range_32(value - j)));
                func(data[:i].tostring() + to_string_32(in_range_32(value - j)) + data[i + 4:].tostring(), default_info)

            # if swap_32(in_range_32(value + j)) == in_range_32(value + j) or swap_32(in_range_32(value - j)) == in_range_32(value - j):
            #    continue

            # big endian increment
            if is_not_bitflip(r3) and in_range_32((swap_32(value) & 0xffff) + j) > 0xffff:
                # log_master("perform big endian %d +%d = %d"%(i,j, swap_32(in_range_32(swap_32(value) + j))));
                func(data[:i].tostring() + to_string_32(swap_32(in_range_32(swap_32(value) + j))) + data[
                                                                                                    i + 4:].tostring(),
                     default_info)

            # big endian decrement
            if is_not_bitflip(r4) and (swap_32(value) & 0xffff) < j:
                # log_master("perform big endian %d -%d = %d"%(i,j, swap_32(in_range_32(swap_32(value) - j))));
                func(data[:i].tostring() + to_string_32(swap_32(in_range_32(swap_32(value) - j))) + data[
                                                                                                    i + 4:].tostring(),
                     default_info)
