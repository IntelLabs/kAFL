# Copyright 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
AFL-style bitflip mutations (deterministic stage).
"""

def walking_bits_execs(data, skip_null=False, effector_map=None):
    execs=0
    for i in range(len(data) * 8):
        if effector_map:
            if not effector_map[i // 8]:
                continue
        if data[i // 8] == 0x00 and skip_null:
            continue

        execs +=1

    return execs


def mutate_seq_walking_bits(data, func, skip_null=False, effector_map=None):
    for i in range(len(data) * 8):
        if effector_map:
            if not effector_map[i // 8]:
                continue
        if data[i // 8] == 0x00 and skip_null:
            continue
        data[i // 8] ^= (0x80 >> (i % 8))
        func(data, label="afl_flip_1/1")
        data[i // 8] ^= (0x80 >> (i % 8))


def mutate_seq_two_walking_bits(data, func, skip_null=False, effector_map=None):
    for i in range((len(data) * 8) - 1):
        if effector_map:
            if not (effector_map[i // 8] or effector_map[(i + 1) // 8]):
                continue
        if data[i // 8] == 0x00 and data[(i + 1) // 8] == 0x00 and skip_null:
            continue
        data[i // 8] ^= (0x80 >> (i % 8))
        data[(i + 1) // 8] ^= (0x80 >> ((i + 1) % 8))
        func(data, label="afl_flip_2/1")
        data[i // 8] ^= (0x80 >> (i % 8))
        data[(i + 1) // 8] ^= (0x80 >> ((i + 1) % 8))


def mutate_seq_four_walking_bits(data, func, skip_null=False, effector_map=None):
    for i in range((len(data) * 8 - 3)):
        if effector_map:
            if not (effector_map[i // 8] or effector_map[(i + 3) // 8]):
                continue
        if data[i // 8] == 0x00 and data[(i + 3) // 8] == 0x00 and skip_null:
            continue

        data[i // 8] ^= (0x80 >> (i % 8))
        data[(i + 1) // 8] ^= (0x80 >> ((i + 1) % 8))
        data[(i + 2) // 8] ^= (0x80 >> ((i + 2) % 8))
        data[(i + 3) // 8] ^= (0x80 >> ((i + 3) % 8))
        func(data, label="afl_flip_4/1")
        data[i // 8] ^= (0x80 >> (i % 8))
        data[(i + 1) // 8] ^= (0x80 >> ((i + 1) % 8))
        data[(i + 2) // 8] ^= (0x80 >> ((i + 2) % 8))
        data[(i + 3) // 8] ^= (0x80 >> ((i + 3) % 8))


def mutate_seq_walking_byte(data, func, effector_map=None, limiter_map=None, skip_null=False):

    if effector_map:
        orig_bitmap, _ = func(data)

    for i in range(len(data)):
        if limiter_map:
            if not limiter_map[i]:
                continue

        if data[i] == 0x00 and skip_null:
            continue

        data[i] ^= 0xFF
        bitmap, _ = func(data, label="afl_flip_8/1")
        if effector_map and orig_bitmap == bitmap:
            effector_map[i] = 0
        data[i] ^= 0xFF


def mutate_seq_two_walking_bytes(data, func, effector_map=None, skip_null=False):
    if len(data) <= 1:
        return

    for i in range(0, len(data)-1):
        if effector_map:
            if effector_map[i:i+2] == b'\x00\x00':
                continue

        if data[i:i+2] == b'\x00\x00' and skip_null:
            continue

        data[i+0] ^= 0xFF
        data[i+1] ^= 0xFF
        func(data, label="afl_flip_8/2")
        data[i+0] ^= 0xFF
        data[i+1] ^= 0xFF


def mutate_seq_four_walking_bytes(data, func, effector_map=None, skip_null=False):
    if len(data) <= 3:
        return

    for i in range(0, len(data)-3):

        if effector_map:
            if effector_map[i:i+4] == b'\x00\x00\x00\x00':
                continue

        if data[i:i+4] == b'\x00\x00\x00\x00' and skip_null:
            continue

        data[i+0] ^= 0xFF
        data[i+1] ^= 0xFF
        data[i+2] ^= 0xFF
        data[i+3] ^= 0xFF
        func(data, label="afl_flip_8/4")
        data[i+0] ^= 0xFF
        data[i+1] ^= 0xFF
        data[i+2] ^= 0xFF
        data[i+3] ^= 0xFF
