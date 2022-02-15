# Copyright 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Reimplementation of AFL-style arithmentic mutations (deterministic stage).
"""

from binascii import hexlify

from kafl_fuzzer.technique.helper import *


def mutate_seq_8_bit_arithmetic(data, func, skip_null=False, effector_map=None, arith_max=AFL_ARITH_MAX, verbose=False):

    label="afl_arith_1"
    for i in range(len(data)):

        if effector_map:
            if not effector_map[i]:
                continue

        orig = data[i]

        if skip_null and orig == 0:
            continue

        for j in range(1, arith_max + 1):

            r1 = (orig + j) & 0xff
            r2 = (orig - j) & 0xff

            if is_not_bitflip(orig^r1):
                data[i] = r1
                func(data, label)

            if is_not_bitflip(orig^r2):
                data[i] = r2
                func(data, label)

        data[i] = orig

def mutate_seq_16_bit_arithmetic(data, func, skip_null=False, effector_map=None, arith_max=AFL_ARITH_MAX, verbose=False):

    label="afl_arith_2"
    for i in range(len(data) - 1):

        if effector_map:
            if effector_map[i:i+2] == bytes(2):
                continue

        orig = data[i:i+2]
        num1 = struct.unpack('<H', (orig))[0]
        num2 = struct.unpack('>H', (orig))[0]

        if skip_null and num1 == 0:
            continue

        for j in range(1, arith_max + 1):

            r1 = (num1 + j) & 0xffff
            r2 = (num1 - j) & 0xffff
            r3 = (num2 + j) & 0xffff
            r4 = (num2 - j) & 0xffff

            if num1^r1 > 0xff and is_not_bitflip(num1^r1):
                struct.pack_into('<H', data, i, r1)
                func(data, label)

            if num1^r2 > 0xff and is_not_bitflip(num1^r2):
                struct.pack_into('<H', data, i, r2)
                func(data, label)

            if num2^r3 > 0xff and swap_16(r1) != r3 and is_not_bitflip(num2^r3):
                struct.pack_into('>H', data, i, r3)
                func(data, label)

            if num2^r4 > 0xff and swap_16(r4) != r4 and is_not_bitflip(num2^r4):
                struct.pack_into('>H', data, i, r4)
                func(data, label)

        data[i:i+2] = orig


def mutate_seq_32_bit_arithmetic(data, func, skip_null=False, effector_map=None, arith_max=AFL_ARITH_MAX, verbose=False):

    label="afl_arith_4"
    for i in range(len(data) - 3):

        if effector_map:
            if effector_map[i:i+4] == bytes(4):
                continue

        orig = data[i:i+4]
        num1 = struct.unpack('<I', (orig))[0]
        num2 = struct.unpack('>I', (orig))[0]

        if skip_null and num1 == 0:
            continue

        for j in range(1, arith_max + 1):

            r1 = (num1 + j) & 0xffffffff
            r2 = (num1 - j) & 0xffffffff
            r3 = (num2 + j) & 0xffffffff
            r4 = (num2 - j) & 0xffffffff

            if num1^r1 > 0xffff and is_not_bitflip(num1^r1):
                struct.pack_into('<I', data, i, r1)
                func(data, label)

            if num1^r2 > 0xffff and is_not_bitflip(num1^r2):
                struct.pack_into('<I', data, i, r2)
                func(data, label)

            if num2^r3 > 0xffff and is_not_bitflip(num2^r3):
                struct.pack_into('>I', data, i, r3)
                func(data, label)

            if num2^r4 > 0xffff and is_not_bitflip(num2^r4):
                struct.pack_into('>I', data, i, r4)
                func(data, label)

        data[i:i+4] = orig
