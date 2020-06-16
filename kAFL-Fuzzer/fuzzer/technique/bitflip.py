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

def bitflip_range(data, skip_null=False, effector_map=None):
    if len(data) == 0:
        return 0

    if effector_map:
        effector_map = effector_map[:len(data)]
        data_len = sum(x is True for x in effector_map)
        data_tmp = ""
        for i in range(len(data)):
            if effector_map[i]:
                data_tmp += data[i]
    else:
        data_len = len(data)
        data_tmp = data
    num = data_len * 8
    num += data_len * 7
    num += data_len * 5
    num += data_len
    if effector_map:
        byte_count = 0
        for i in range(len(data)):
            if effector_map[i]:
                byte_count += 1
                if byte_count >= 2:
                    num += 1
                if byte_count >= 4:
                    num += 1

            else:
                byte_count = 0
    else:
        if data_len > 1:
            num += data_len - 1
        if data_len > 3:
            num += data_len - 3
    return num


def bitflip8_range(data, skip_null=False, effector_map=None):
    if effector_map:
        effector_map = effector_map[:len(data)]
        data_len = sum(x is True for x in effector_map)
        data_tmp = ""
        for i in range(len(data)):
            if effector_map[i]:
                data_tmp += data[i]
    else:
        data_len = len(data)
        data_tmp = data
    num = data_len * 8
    return num


def mutate_seq_walking_bits_array(data, func, default_info, skip_null=False, effector_map=None):
    for i in xrange(len(data) * 8):
        if effector_map:
            if not effector_map[i / 8]:
                continue
        if data[i / 8] == 0x00 and skip_null:
            func(None, no_data=True)
            continue
        data[i / 8] ^= (0x80 >> (i % 8))
        func(data.tostring(), default_info)
        data[i / 8] ^= (0x80 >> (i % 8))


def mutate_seq_two_walking_bits_array(data, func, default_info, skip_null=False, effector_map=None):
    for i in range((len(data) * 8) - 1):
        if effector_map:
            if not (effector_map[i / 8] or effector_map[(i + 1) / 8]):
                continue
        if data[i / 8] == 0x00 and data[(i + 1) / 8] == 0x00 and skip_null:
            func(None, no_data=True)
            continue
        data[i / 8] ^= (0x80 >> (i % 8))
        data[(i + 1) / 8] ^= (0x80 >> ((i + 1) % 8))
        func(data.tostring(), default_info)
        data[i / 8] ^= (0x80 >> (i % 8))
        data[(i + 1) / 8] ^= (0x80 >> ((i + 1) % 8))


def mutate_seq_four_walking_bits_array(data, func, default_info, skip_null=False, effector_map=None):
    for i in range((len(data) * 8 - 3)):
        if effector_map:
            if not (effector_map[i / 8] or effector_map[(i + 3) / 8]):
                continue
        if data[i / 8] == 0x00 and data[(i + 3) / 8] == 0x00 and skip_null:
            func(None, no_data=True)
            continue

        data[i / 8] ^= (0x80 >> (i % 8))
        data[(i + 1) / 8] ^= (0x80 >> ((i + 1) % 8))
        data[(i + 2) / 8] ^= (0x80 >> ((i + 2) % 8))
        data[(i + 3) / 8] ^= (0x80 >> ((i + 3) % 8))
        func(data.tostring(), default_info)
        data[i / 8] ^= (0x80 >> (i % 8))
        data[(i + 1) / 8] ^= (0x80 >> ((i + 1) % 8))
        data[(i + 2) / 8] ^= (0x80 >> ((i + 2) % 8))
        data[(i + 3) / 8] ^= (0x80 >> ((i + 3) % 8))


def mutate_seq_walking_byte_array(data, func, default_info, effector_map, limiter_map, skip_null=False):
    orig_bitmap, _ = func(data.tostring(), default_info)
    # mmh3.hash64(bitmap)
    for i in range((len(data))):
        if limiter_map:
            if not limiter_map[i]:
                continue
        if data[i] == 0x00 and skip_null:
            continue
        data[i] ^= 0xFF
        bitmap, _ = func(data.tostring(), default_info)
        if effector_map and orig_bitmap == bitmap:
            effector_map[i] = 0
        data[i] ^= 0xFF


def mutate_seq_two_walking_bytes_array(data, func, default_info, effector_map=None):
    if len(data) > 1:
        for i in range(1, ((len(data)))):
            if effector_map:
                if not (effector_map[i] or effector_map[i - 1]):
                    continue
            data[i] ^= 0xFF
            data[i - 1] ^= 0xFF
            func(data.tostring(), default_info)
            data[i] ^= 0xFF
            data[i - 1] ^= 0xFF


def mutate_seq_four_walking_bytes_array(data, func, default_info, effector_map=None):
    if len(data) > 3:
        for i in range(3, (len(data))):
            if effector_map:
                if not (effector_map[i] or effector_map[i - 1] or effector_map[i - 2] or effector_map[i - 3]):
                    continue
            data[i - 0] ^= 0xFF
            data[i - 1] ^= 0xFF
            data[i - 2] ^= 0xFF
            data[i - 3] ^= 0xFF
            func(data.tostring(), default_info)
            data[i - 0] ^= 0xFF
            data[i - 1] ^= 0xFF
            data[i - 2] ^= 0xFF
            data[i - 3] ^= 0xFF
