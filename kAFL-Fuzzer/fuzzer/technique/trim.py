# Copyright (C) 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright (C) 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
AFL-style trim algorithms (init stage)
"""

from fuzzer.bitmap import GlobalBitmap
from common.log import logger

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


def check_trim_still_valid(old_node, old_res, new_res):
    # non-det input
    if not new_res:
        return False
    if not new_res.is_lut_applied():
        new_res.apply_lut()
    trim_simple = False
    if trim_simple:
        assert False  # todo fixme wrt to bitmaps, == doesnt work on bitmap_wrapper
        return old_res == new_res
    else:
        old_bits = old_node["new_bytes"].copy()
        old_bits.update(old_node["new_bits"])
        return GlobalBitmap.all_new_bits_still_set(old_bits, new_res)


def perform_center_trim(payload, old_node, send_handler, trimming_bytes=2):
    index = 0

    if len(payload) > 2048:
        return payload
    if len(payload) > 1024:
        index = len(payload)//3

    old_res, _ = send_handler(payload, label="center_trim_funky")
    if old_res.is_crash():
        return payload

    while index < len(payload):
        test_payload = payload[0: index] + payload[index + trimming_bytes:]
        exec_res, _ = send_handler(test_payload, label="center_trim")

        if check_trim_still_valid(old_node, old_res, exec_res):
            payload = test_payload[:]
        else:
            index += trimming_bytes

    return payload

# Search a padding extension that does not make the target report a STARVED status.
#
# The target should pad with 0 by default so that length-extending with 0 here is a NOP.
# However, it seems we can still get bitmap changes sometimes, i.e. the extension failed.
# So we also try some colorized padding at this point, in hope of triggering the starved logic.
def perform_extend(payload, old_node, send_handler, max_len):

    num_findings = 0

    # Skip if payload is not starved, not regular or funky (test run yields is_new=True)
    old_res, is_new = send_handler(payload, label="stream_funky")
    if old_res.is_crash() or not old_res.is_starved() or is_new:
        return None

    padding = 128
    upper = max(0, max_len - len(payload))
    lower = 0
    for _ in range(2*MAX_ROUNDS):
        try:
            new_res, is_new = send_handler(payload + bytes(padding), label="stream_extend")
        except:
            print("Round: %d, lengths: %d + %d = %d, maxlen=%d, upper=%d, lower=%d" %(
                _, len(payload), padding, padding+len(payload), max_len, upper, lower))

        if is_new: num_findings += 1

        if new_res.is_starved():
            lower = padding
        else:
            upper = padding

        #print("stream_extend: upper=%d, lower=%d" % (upper, lower))
        padding = lower + abs(upper - lower)//2
        if abs(upper - lower) <= 1:
            break

        if (len(payload) + padding > max_len):
            upper = max(0, max_len - len(payload))
            break

    pad_bytes = upper
    logger.debug("stream_extend: pad_bytes=%d" % (pad_bytes))

    if pad_bytes == 0:
        return None

    # run the payload with some colorized padding to potentially trigger the starved code
    pad_buffer = bytes(range(pad_bytes%256))
    for _ in range(pad_bytes//256):
        pad_buffer += bytes(range(256))
    for i in range(min(len(pad_buffer),32)):
        _, is_new = send_handler(payload + pad_buffer[i:] + pad_buffer[:i], label="stream_color")
        if is_new: num_findings += 1

    # check if zero-padded payload is still valid, drop otherwise..
    new_res, is_new = send_handler(payload + bytes(pad_bytes), label="stream_extend")
    if is_new: num_findings += 1
    if check_trim_still_valid(old_node, old_res, new_res):
        return payload + bytes(pad_bytes)
    else:
        logger.debug("stream_extend: dropped funky NUL padding (len=%d, other finds=%d)" % (pad_bytes, num_findings))
        return None


def perform_trim(payload, old_node, send_handler):
    global MAX_ROUNDS, MAX_EXECS, MIN_SIZE, APPEND_BYTES
    if len(payload) <= MIN_SIZE:
        return payload

    old_res, _ = send_handler(payload, label="trim_funky")
    if old_res.is_crash():
        return payload

    execs = 0
    new_size = len(payload)

    for _ in range(MAX_ROUNDS):
        abort = True
        for i in reversed(range(0, pow2_values.index(get_pow2_value(new_size)) + 1)):
            if pow2_values[i] < new_size:

                execs += 1
                if execs == MAX_EXECS:
                    abort = True
                    break

                new_res, _ = send_handler(payload[0:new_size - pow2_values[i]], label="trim")

                if new_res.is_crash():
                    return payload[0:new_size]

                if check_trim_still_valid(old_node, old_res, new_res):
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

    new_res, _ = send_handler(payload[0:new_size], label="trim")
    if not check_trim_still_valid(old_node, old_res, new_res):
        return payload[0:min(new_size_backup, len(payload))]

    return payload[0:min(new_size, len(payload))]
