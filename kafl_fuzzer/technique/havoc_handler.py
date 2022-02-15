# Copyright (C) 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright (C) 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
AFL-style havoc mutations (havoc stage)
"""

from common.log import logger
from common.util import read_binary_file, find_diffs
from fuzzer.technique.helper import *

def insert_word(data, chars, term):
    if len(data) < 2:
        return data

    offset = rand.int(len(data))
    if rand.int(2) > 1:
        replen = 0  # plain insert
    else:
        replen = rand.int(len(data) - offset)

    word_length = min(len(data) - offset, rand.int(10) + 1)

    body = ''.join([term] + [rand.select(chars) for _ in range(word_length - 1)] + [term])
    return b''.join([data[:offset], body.encode(), data[offset+replen:]])


def havoc_insert_line(data):
    alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxy"
    num = "0123456789.,x"
    special = "!\"$%&/()=?`'#+*+-_,.;:\\{[]}<>"
    terminator = ["\n", " ", "\0", '""', "'", "", " ADF\n"]
    return insert_word(data, rand.select([alpha, num, special]), rand.select(terminator))


def havoc_perform_bit_flip(data):
    if len(data) < 1:
        return data

    bit = rand.int(len(data)*8)
    pos = bit//8

    value = data[pos] ^ (0x80 >> (bit % 8))
    return b''.join([data[:pos], value.to_bytes(1, 'little', signed=False), data[pos+1:]])


def havoc_perform_insert_interesting_value_8(data):
    if len(data) < 1:
        return data

    pos = rand.int(len(data))
    value = rand.select(interesting_8_Bit)

    return b''.join([data[:pos], value.to_bytes(1, 'little', signed=True), data[pos+1:]])


def havoc_perform_insert_interesting_value_16(data):
    if len(data) < 2:
        return data

    order = rand.select(("big", "little"))
    pos = rand.int(len(data) - 1)
    value = rand.select(interesting_16_Bit)

    return b''.join([data[:pos], value.to_bytes(2, order, signed=True), data[pos+2:]])


def havoc_perform_insert_interesting_value_32(data):
    if len(data) < 4:
        return data

    order = rand.select(("big", "little"))
    pos = rand.int(len(data) - 3)
    value = rand.select(interesting_32_Bit)

    return b''.join([data[:pos], value.to_bytes(4, order, signed=True), data[pos+4:]])


def havoc_perform_byte_subtraction_8(data):
    if len(data) < 1:
        return data

    pos = rand.int(len(data))
    value = int.from_bytes(data[pos:pos+1], 'little', signed=False)
    value = (value - 1 - rand.int(AFL_ARITH_MAX)) % 0xff

    return b''.join([data[:pos], value.to_bytes(1, 'little', signed=False), data[pos+1:]])


def havoc_perform_byte_addition_8(data):
    if len(data) < 1:
        return data

    pos = rand.int(len(data))
    value = int.from_bytes(data[pos:pos+1], 'little', signed=False)
    value = (value + 1 + rand.int(AFL_ARITH_MAX)) % 0xff

    return b''.join([data[:pos], value.to_bytes(1, 'little', signed=False), data[pos+1:]])


def havoc_perform_byte_subtraction_16(data):
    if len(data) < 2:
        return data

    order = rand.select(("big", "little"))
    pos = rand.int(len(data) - 1)
    value = int.from_bytes(data[pos:pos+2], order, signed=False)
    value = (value - 1 - rand.int(AFL_ARITH_MAX)) % 0xffff

    return b''.join([data[:pos], value.to_bytes(2, order, signed=False), data[pos+2:]])


def havoc_perform_byte_addition_16(data):
    if len(data) < 2:
        return data

    order = rand.select(("big", "little"))
    pos = rand.int(len(data) - 1)
    value = int.from_bytes(data[pos:pos+2], order, signed=False)
    value = (value + 1 + rand.int(AFL_ARITH_MAX)) % 0xffff

    return b''.join([data[:pos], value.to_bytes(2, order, signed=False), data[pos+2:]])


def havoc_perform_byte_subtraction_32(data):
    if len(data) < 4:
        return data

    order = rand.select(("big", "little"))
    pos = rand.int(len(data) - 3)
    value = int.from_bytes(data[pos:pos+4], order, signed=False)
    value = (value - 1 - rand.int(AFL_ARITH_MAX)) % 0xffffffff

    return b''.join([data[:pos], value.to_bytes(4, order, signed=False), data[pos+4:]])


def havoc_perform_byte_addition_32(data):
    if len(data) < 4:
        return data

    order = rand.select(("big", "little"))
    pos = rand.int(len(data) - 3)
    value = int.from_bytes(data[pos:pos+4], order, signed=False)
    value = (value + 1 + rand.int(AFL_ARITH_MAX)) % 0xffffffff

    return b''.join([data[:pos], value.to_bytes(4, order, signed=False), data[pos+4:]])

def havoc_perform_set_random_byte_value(data):
    if len(data) < 1:
        return data

    pos = rand.int(len(data))
    value = data[pos] ^ (1 + rand.int(255))

    return b''.join([data[:pos], value.to_bytes(1, 'little', signed=False), data[pos+1:]])


def havoc_perform_delete_random_byte(data):
    if len(data) < 2:
        return data

    del_length = AFL_choose_block_len(len(data) - 1)
    del_from = rand.int(len(data) - del_length + 1)
    return b''.join([data[:del_from] + data[del_from + del_length:]])


def havoc_perform_clone_random_byte(data):
    data_len = len(data)

    if data_len < 1 or data_len + HAVOC_BLK_XL >= KAFL_MAX_FILE:
        return data

    # clone bytes with p=3/4, else insert block of constant bytes
    if rand.int(4):
        clone_len = AFL_choose_block_len(data_len)
        clone_from = rand.int(data_len - clone_len + 1)
        body = data[clone_from: clone_from + clone_len]
    else:
        clone_len = AFL_choose_block_len(HAVOC_BLK_XL)
        val = rand.int(256) if rand.int(2) else rand.select(data)
        body = b''.join([val.to_bytes(1, 'little', signed=False) for _ in range(clone_len)])

    clone_to = rand.int(data_len)
    return b''.join([data[:clone_to], body, data[clone_to:]])

def havoc_perform_byte_seq_override(data):

    if len(data) < 2:
        return data

    copy_len = AFL_choose_block_len(len(data) - 1)
    copy_from = rand.int(len(data) - copy_len + 1)
    copy_to = rand.int(len(data) - copy_len + 1)

    body = b''

    if rand.int(4):
        if copy_from != copy_to:
            body = data[copy_from: copy_from + copy_len]
    else:
        if rand.int(2):
            value = rand.int(256)
        else:
            value = rand.select(data)
        body = b''.join(value.to_bytes(1, 'little', signed=False) for _ in range(copy_len))

    return b''.join([data[:copy_to], body, data[copy_to+copy_len:]])


def havoc_perform_byte_seq_extra1(data):
    pass


def havoc_perform_byte_seq_extra2(data):
    pass


def havoc_splicing(data, files):
    if len(data) < 2 or files is None:
        return data

    rand.shuffle(files)
    retry_limit = 64

    for file in files[:retry_limit]:
        file_data = read_binary_file(file)
        if len(file_data) < 2:
            continue

        first_diff, last_diff = find_diffs(data, file_data)
        if last_diff < 2 or first_diff == last_diff:
            continue

        split_location = first_diff + rand.int(last_diff - first_diff)
        return data[:split_location] + file_data[split_location:]

    # none of the files are suitable
    return None


dict_set = set()
dict_import = []

redqueen_dict = {}
redqueen_addr_list = []
redqueen_known_addrs = set()
redqueen_seen_addr_to_value = {}


def set_dict(new_dict):
    global dict_import
    dict_import = new_dict
    dict_set = set(new_dict)


def clear_redqueen_dict():
    global redqueen_dict, redqueen_addr_list
    #logger.debug("Redqueen: clearing dict %s" % repr(redqueen_dict))
    redqueen_dict = {}
    redqueen_addr_list = []


def get_redqueen_dict():
    global redqueen_dict
    return redqueen_dict


def get_redqueen_seen_addr_to_value():
    global redqueen_seen_addr_to_value
    return redqueen_seen_addr_to_value


def add_to_redqueen_dict(addr, val):
    global redqueen_dict, redqueen_addr_list

    assert len(redqueen_dict) == len(redqueen_addr_list)

    val = val[:16]
    for v in val.split(b'0'):
        if len(v) > 3:
            if not addr in redqueen_dict:
                redqueen_dict[addr] = set()
                redqueen_addr_list.append(addr)
            #logger.debug("Redqueen: Added Dynamic Dict: %s"%repr(v))
            redqueen_dict[addr].add(v)


def append_handler(handler):
    global havoc_handler
    havoc_handler.append(handler)


# placing dict entry at variable offset overlapping the end should also be useful?
def dict_insert_sequence(data, entry, entry_pos=None):
    #logger.debug("HAVOC DICT-INS: %s [%s] -> %s " % (repr(data), repr(entry), repr(newdata)))
    if entry_pos is None:
        entry_pos = rand.int(max([0, len(data) - len(entry)]))
    return b''.join([data[:entry_pos], entry, data[entry_pos+len(entry):]])

def dict_replace_sequence(data, entry, entry_pos=None):
    #logger.debug("HAVOC DICT-REP: %s [%s] -> %s " % (repr(data), repr(entry), repr(newdata)))
    if entry_pos is None:
        entry_pos = rand.int(max([0, len(data) - len(entry)]))
    return b''.join([data[:entry_pos], entry, data[entry_pos:]])

def havoc_dict_insert(data):
    global redqueen_dict
    global dict_import

    has_redq = len(redqueen_dict) > 0
    has_dict = len(dict_import) > 0
    coin = rand.int(2)

    if not has_dict and has_redq and coin:
        addr = rand.select(redqueen_addr_list)
        dict_values = list(redqueen_dict[addr])
        dict_entry = rand.select(dict_values)
        return dict_insert_sequence(data, dict_entry)

    elif has_dict:
        dict_entry = rand.select(dict_import)
        #dict_entry = dict_entry[:len(data)]
        return dict_insert_sequence(data, dict_entry)
    return data

def havoc_dict_replace(data):
    global redqueen_dict
    global dict_import

    has_redq = len(redqueen_dict) > 0
    has_dict = len(dict_import) > 0
    coin = rand.int(2)

    if not has_dict and has_redq and coin:
        addr = rand.select(redqueen_addr_list)
        dict_values = list(redqueen_dict[addr])
        dict_entry = rand.select(dict_values)
        return dict_replace_sequence(data, dict_entry)

    elif has_dict:
        dict_entry = rand.select(dict_import)
        #dict_entry = dict_entry[:len(data)]
        return dict_replace_sequence(data, dict_entry)
    return data



havoc_handler = [havoc_perform_bit_flip,
                 havoc_perform_insert_interesting_value_8,
                 havoc_perform_insert_interesting_value_16,
                 havoc_perform_insert_interesting_value_32,
                 havoc_perform_byte_subtraction_8,
                 havoc_perform_byte_addition_8,
                 havoc_perform_byte_subtraction_16,
                 havoc_perform_byte_addition_16,
                 havoc_perform_byte_subtraction_32,
                 havoc_perform_byte_addition_32,
                 havoc_perform_set_random_byte_value,
                 havoc_perform_delete_random_byte,
                 havoc_perform_delete_random_byte,
                 havoc_perform_clone_random_byte,
                 havoc_perform_byte_seq_override,
                 # dict mutators are initialized in havoc_init()
                 #havoc_dict_insert,
                 #havoc_dict_replace,

                 # havoc_perform_byte_seq_extra1,
                 # havoc_perform_byte_seq_extra2,
                 # havoc_insert_line,
                 ]
