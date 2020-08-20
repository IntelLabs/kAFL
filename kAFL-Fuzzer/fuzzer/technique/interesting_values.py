# Copyright (C) 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright (C) 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
AFL-style 'interesting values' mutations (deterministic stage).
"""

from fuzzer.technique.helper import *
from binascii import hexlify


def mutate_seq_8_bit_interesting(data, func, skip_null=False, effector_map=None, verbose=False):

    label="afl_int_1"
    for i in range(0, len(data)):
        if effector_map:
            if not effector_map[i]:
                continue

        orig = data[i]

        if skip_null and orig == 0:
            continue

        for j in range(len(interesting_8_Bit)):
            value = in_range_8(interesting_8_Bit[j])
            # TODO: should check with arith_max value here?
            if (is_not_bitflip(orig ^ value) and
                is_not_arithmetic(orig, value, 1)):
                    data[i] = value
                    func(data, label=label)

        data[i] = orig


def mutate_seq_16_bit_interesting(data, func, skip_null=False, effector_map=None, arith_max=AFL_ARITH_MAX, verbose=False):

    label="afl_int_2"
    for i in range(len(data) - 1):
        if effector_map:
            if not (effector_map[i] or effector_map[i + 1]):
                continue

        orig = data[i:i+2]
        oval = struct.unpack('<H', orig)[0]

        if skip_null and oval == 0:
            continue

        for j in range(len(interesting_16_Bit)):
            num1 = in_range_16(interesting_16_Bit[j])
            num2 = swap_16(num1)

            if (is_not_bitflip(oval ^ num1) and
                is_not_arithmetic(oval, num1, 2, arith_max=arith_max) and
                is_not_interesting(oval, num1, 2, 0)):
                    data[i:i+2] = struct.pack("<H", num1)
                    func(data, label=label)

            if (num1 != num2 and \
                is_not_bitflip(oval ^ num2) and \
                is_not_arithmetic(oval, num2, 2, arith_max=arith_max) and \
                is_not_interesting(oval, num2, 2, 1)):
                    data[i:i+2] = struct.pack(">H", num1)
                    func(data, label=label)

        data[i:i+2] = orig


def mutate_seq_32_bit_interesting(data, func, skip_null=False, effector_map=None, arith_max=AFL_ARITH_MAX, verbose=False):

    label="afl_int_4"
    for i in range(len(data) - 3):
        if effector_map:
            if effector_map[i:i+4] == b'\x00\x00\x00\x00':
                continue

        orig = data[i:i+4]
        oval = struct.unpack('<I', orig)[0]

        if skip_null and oval == 0:
            continue

        for j in range(len(interesting_32_Bit)):

            num1 = in_range_32(interesting_32_Bit[j])
            num2 = swap_32(num1)

            if (is_not_bitflip(oval ^ num1) and \
                is_not_arithmetic(oval, num1, 4, arith_max=arith_max) and \
                is_not_interesting(oval, num1, 4, 0)):
                    data[i:i+4] = struct.pack("<I", num1)
                    func(data, label=label)

            if (num1 != num2 and is_not_bitflip(oval ^ num2) and
                is_not_arithmetic(oval, num2, 4, arith_max=arith_max) and
                is_not_interesting(oval, num2, 4, 1)):
                    data[i:i+4] = struct.pack("<I", num2)
                    func(data, label=label)

        data[i:i+4] = orig
