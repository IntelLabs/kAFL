# Copyright 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Reimplementation of AFL-style arithmentic mutations (deterministic stage).
"""


from fuzzer.technique.helper import *
from binascii import hexlify


def mutate_seq_8_bit_arithmetic(data, func, skip_null=False, effector_map=None, arith_max=AFL_ARITH_MAX, verbose=False):

    label="afl_arith_1"
    for i in range(0, len(data)):

        if effector_map:
            if not effector_map[i]:
                continue

        orig = data[i]

        if skip_null and orig == 0:
            continue

        for j in range(1, arith_max + 1):

            r1 = (orig + j) & 0xff
            r2 = (orig - j) & 0xff

            data[i] = r1
            if is_not_bitflip(orig^r1):
                func(data, label)
            elif verbose:
                print("Skip_01: ", hexlify(data), " diff: 0x%02x, value=%2d" % (orig^r1, orig+j))

            data[i] = r2
            if is_not_bitflip(orig^r2):
                func(data, label)
            elif verbose:
                print("Skip_02: ", hexlify(data), " diff: 0x%02x, value=%2d" % (orig^r2, orig-j))

        data[i] = orig

def mutate_seq_16_bit_arithmetic(data, func, skip_null=False, effector_map=None, arith_max=AFL_ARITH_MAX, verbose=False):

    label="afl_arith_2"
    for i in range(0, len(data) - 1):

        if effector_map:
            if effector_map[i:i+2] == b'\x00\x00':
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

            if is_not_bitflip(num1^r1) and num1^r1 > 0xff:
                data[i:i+2] = struct.pack('<H', r1)
                func(data, label)
            elif verbose:
                data[i:i+2] = struct.pack('<H', r1)
                print("Skip_01: ", hexlify(data), " diff: 0x%04x, value=%3d" % (num1^r1, num1+j))

            if is_not_bitflip(num1^r2) and num1^r2 > 0xff:
                data[i:i+2] = struct.pack('<H', r2)
                func(data, label)
            elif verbose:
                data[i:i+2] = struct.pack('<H', r2)
                print("Skip_02: ", hexlify(data), " diff: 0x%04x, value=%3d" % (num1^r2, num1-j))

            if is_not_bitflip(num2^r3) and swap_16(r1) != r3 and num2^r3 > 0xff:
                data[i:i+2] = struct.pack('>H', r3)
                func(data, label)
            elif verbose:
                data[i:i+2] = struct.pack('>H', r3)
                print("Skip_03: ", hexlify(data), " diff: 0x%04x, value=%3d" % (num2^r3, num2+j))

            if is_not_bitflip(num2^r4) and swap_16(r2) != r4 and num2^r4 > 0xff:
                data[i:i+2] = struct.pack('>H', r4)
                func(data, label)
            elif verbose:
                data[i:i+2] = struct.pack('>H', r4)
                print("Skip_04: ", hexlify(data), " diff: 0x%04x, value=%3d" % (num2^r4, num2-j))

        data[i:i+2] = orig


def mutate_seq_32_bit_arithmetic(data, func, skip_null=False, effector_map=None, arith_max=AFL_ARITH_MAX, verbose=False):

    label="afl_arith_4"
    for i in range(0, len(data) - 3):

        if effector_map:
            if effector_map[i:i+4] == b'\x00\x00\x00\x00':
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

            if is_not_bitflip(num1^r1) and (num1 & 0xffff) +j > 0xffff:
                data[i:i+4] = struct.pack('<I', r1)
                func(data, label)
            elif verbose:
                data[i:i+4] = struct.pack('<I', r1)
                print("Skip_01: ", hexlify(data), " diff: 0x%08x, value=%8d" % (num1^r1, num1+j))

            if is_not_bitflip(num1^r2) and num1 & 0xffff < j:
                data[i:i+4] = struct.pack('<I', r2)
                func(data, label)
            elif verbose:
                data[i:i+4] = struct.pack('<I', r2)
                print("Skip_02: ", hexlify(data), " diff: 0x%08x, value=%8d" % (num1^r2, num1-j))

            if is_not_bitflip(num2^r3) and (num2 & 0xffff) +j > 0xffff:
                data[i:i+4] = struct.pack('>I', r3)
                func(data, label)
            elif verbose:
                data[i:i+4] = struct.pack('>I', r3)
                print("Skip_03: ", hexlify(data), " diff: 0x%08x, value=%8d" % (num2^r3, num2+j))

            if is_not_bitflip(num2^r4) and num2 & 0xffff < j:
                data[i:i+4] = struct.pack('>I', r4)
                func(data, label)
            elif verbose:
                data[i:i+4] = struct.pack('>I', r4)
                print("Skip_04: ", hexlify(data), " diff: 0x%08x, value=%8d" % (num2^r4, num2-j))

        data[i:i+4] = orig
