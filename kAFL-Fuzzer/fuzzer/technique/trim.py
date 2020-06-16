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

from fuzzer.bitmap import GlobalBitmap

MAX_EXECS = 16
MAX_ROUNDS = 32
MIN_SIZE = 32
APPEND_VALUE = 0.1

APPEND_BYTES = 16

pow2_values = [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768]


def get_pow2_value(value):
    for pow2_value in reversed(pow2_values):
        if pow2_value <= value:
            return pow2_value
    return 1


def check_trim_still_valid(old_node, old_bitmap, new_bitmap):
    # non-det input
    if not new_bitmap:
        return False
    if not new_bitmap.is_lut_applied():
        new_bitmap.apply_lut()
    trim_simple = False
    if trim_simple:
        assert False  # todo fixme wrt to bitmaps, == doesnt work on bitmap_wrapper
        return old_bitmap == new_bitmap
    else:
        old_bits = old_node["new_bytes"].copy()
        old_bits.update(old_node["new_bits"])
        return GlobalBitmap.all_new_bits_still_set(old_bits, new_bitmap)


def perform_center_trim(payload, old_node, send_handler, default_info, error_handler, trimming_bytes):
    index = 0
    old_bitmap, _ = send_handler(payload, default_info)

    if error_handler():
        return payload

    while index < len(payload):
        test_payload = payload[0: index] + payload[index + trimming_bytes:]

        new_bitmap, _ = send_handler(test_payload, default_info)

        # if error_handler():
        #     return payload

        if check_trim_still_valid(old_node, old_bitmap, new_bitmap):
            payload = test_payload[:]
        else:
            index += trimming_bytes

    return payload


def perform_trim(payload, old_node, send_handler, default_info, error_handler):
    global MAX_ROUNDS, MAX_EXECS, MIN_SIZE, APPEND_BYTES
    if len(payload) <= MIN_SIZE:
        return payload

    old_bitmap, _ = send_handler(payload, default_info)
    if error_handler():
        return payload
    execs = 0
    new_size = len(payload)

    for _ in xrange(MAX_ROUNDS):
        abort = True
        for i in reversed(xrange(0, pow2_values.index(get_pow2_value(new_size)) + 1)):
            if pow2_values[i] < new_size:

                execs += 1
                if execs == MAX_EXECS:
                    abort = True
                    break

                new_bitmap, _ = send_handler(payload[0:new_size - pow2_values[i]], default_info)

                if error_handler():
                    return payload[0:new_size]

                if check_trim_still_valid(old_node, old_bitmap, new_bitmap):
                    new_size -= pow2_values[i]
                    abort = False
                    break

                if new_size <= MIN_SIZE:
                    break

        if abort:
            break

    new_size_backup = new_size
    if new_size < MIN_SIZE:
        new_size = MIN_SIZE
    elif (new_size + int(new_size * APPEND_VALUE)) < len(payload):
        new_size += int(new_size * APPEND_VALUE)

    new_size += APPEND_BYTES

    new_bitmap, _ = send_handler(payload[0:new_size], default_info)
    if not check_trim_still_valid(old_node, old_bitmap, new_bitmap):
        return payload[0:min(new_size_backup, len(payload))]

    return payload[0:min(new_size, len(payload))]
