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

from array import array

from common.debug import log_redq
from common.util import read_binary_file, find_diffs
from fuzzer.technique.helper import *


def insert_word(data, charset, start, term):
    if len(data) >= 2:
        offset = RAND(len(data))
        if RAND(2) > 1:
            repllen = 0  # plain insert
        else:
            replen = RAND(len(data) - offset)

        word_length = min(len(data) - offset, RAND(10) + 1)

        head = data[:offset].tostring()
        tail = data[offset + replen:].tostring()

        body = "".join([charset[RAND(len(charset))] for _ in xrange(word_length - 1)])
        inputstr = head + term + body + term + tail
        return array("B", inputstr)
    return data


def havoc_insert_line(data):
    alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxy"
    num = "0123456789.,x"
    special = "!\"$%&/()=?`'#+*+-_,.;:\\{[]}<>"
    charsets = [alpha, num, special]
    terminator = ["\n", " ", "\0", '""', "'", "", " ADF\n"]
    start_term = terminator[RAND(len(terminator))]
    end_term = terminator[RAND(len(terminator))]
    return insert_word(data, charsets[RAND(len(charsets))], start_term, end_term)


def havoc_perform_bit_flip(data):
    if len(data) >= 1:
        bit = RAND(len(data) << 3)
        data[bit / 8] ^= 0x80 >> (bit % 8)
    return data


def havoc_perform_insert_interesting_value_8(data):
    if len(data) >= 1:
        offset = RAND(len(data))
        value_index = RAND(len(interesting_8_Bit))
        data[offset] = in_range_8(interesting_8_Bit[value_index])
    return data


def havoc_perform_insert_interesting_value_16(data):
    if len(data) >= 2:
        little = RAND(2)
        pos = RAND(len(data) - 1)
        value_index = RAND(len(interesting_16_Bit))
        interesting_value = in_range_16(interesting_16_Bit[value_index])
        if little == 0:
            interesting_value = swap_16(interesting_value)
        store_16(data, pos, interesting_value)
    return data


def havoc_perform_insert_interesting_value_32(data):
    if len(data) >= 4:

        little = RAND(2)
        pos = RAND(len(data) - 3)
        interesting_value = in_range_32(interesting_32_Bit[RAND(len(interesting_32_Bit))])
        if little == 0:
            interesting_value = swap_32(interesting_value)
        store_32(data, pos, interesting_value)
    return data


def havoc_perform_byte_subtraction_8(data):
    if len(data) >= 1:
        delta = RAND(AFL_ARITH_MAX)
        pos = RAND(len(data))
        value = load_8(data, pos)
        value -= 1 + delta
        store_8(data, pos, value)
    return data


def havoc_perform_byte_addition_8(data):
    if len(data) >= 1:
        delta = RAND(AFL_ARITH_MAX)
        pos = RAND(len(data))
        value = load_8(data, pos)
        value += 1 + delta
        store_8(data, pos, value)
    return data


def havoc_perform_byte_subtraction_16(data):
    if len(data) >= 2:
        little = RAND(2)
        pos = RAND(len(data) - 1)
        value = load_16(data, pos)
        if little == 0:
            value = swap_16(swap_16(value) - (1 + RAND(AFL_ARITH_MAX)))
        else:
            value -= 1 + RAND(AFL_ARITH_MAX)
        store_16(data, pos, value)
    return data


def havoc_perform_byte_addition_16(data):
    if len(data) >= 2:
        little = RAND(2)
        pos = RAND(len(data) - 1)
        value = load_16(data, pos)
        if little == 0:
            value = swap_16(swap_16(value) + (1 + RAND(AFL_ARITH_MAX)))
        else:
            value += 1 + RAND(AFL_ARITH_MAX)
        store_16(data, pos, value)
    return data


def havoc_perform_byte_subtraction_32(data):
    if len(data) >= 4:
        little = RAND(2)
        pos = RAND(len(data) - 3)
        value = load_32(data, pos)
        if little == 0:
            value = swap_32(swap_32(value) - (1 + RAND(AFL_ARITH_MAX)))
        else:
            value -= 1 + RAND(AFL_ARITH_MAX)
        store_32(data, pos, value)
    return data


def havoc_perform_byte_addition_32(data):
    if len(data) >= 4:
        little = RAND(2)
        pos = RAND(len(data) - 3)
        value = load_32(data, pos)
        if little == 0:
            value = swap_32(swap_32(value) + (1 + RAND(AFL_ARITH_MAX)))
        else:
            value += 1 + RAND(AFL_ARITH_MAX)
        store_32(data, pos, value)
    return data


def havoc_perform_set_random_byte_value(data):
    if len(data) >= 1:
        delta = 1 + RAND(0xff)
        data[RAND(len(data))] ^= delta
    return data


# Todo: somehow broken :-(
def havoc_perform_delete_random_byte(data):
    if len(data) >= 2:
        del_length = AFL_choose_block_len(len(data) - 1)
        del_from = RAND(len(data) - del_length + 1)
        data = data[:del_from] + data[del_from + del_length:]
    return data


def havoc_perform_clone_random_byte(data):
    temp_len = len(data)
    if len(data) > 2:
        if (temp_len + HAVOC_BLK_LARGE) < KAFL_MAX_FILE:
            actually_clone = RAND(4);
            if actually_clone != 0:
                clone_len = AFL_choose_block_len(temp_len);
                clone_from = RAND(temp_len - clone_len + 1);
            else:
                clone_len = AFL_choose_block_len(HAVOC_BLK_XL);
                clone_from = 0;

            clone_to = RAND(temp_len);

            head = data[:clone_to].tostring()

            if actually_clone != 0:
                body = data[clone_from: clone_from + clone_len].tostring()
            else:
                if RAND(2) != 0:
                    val = chr(RAND(256))
                else:
                    val = chr(data[RAND(temp_len)])
                body = ''.join(val for _ in range(clone_len))

            tail = data[clone_to:].tostring()
            data = array('B', head + body + tail)
    return data


def havoc_perform_byte_seq_override(data):
    if len(data) >= 2:
        copy_length = AFL_choose_block_len(len(data) - 1)
        copy_from = RAND(len(data) - copy_length + 1)
        copy_to = RAND(len(data) - copy_length + 1)
        if RAND(4) != 0:
            if copy_from != copy_to:
                chunk = data[copy_from: copy_from + copy_length]
                for i in range(len(chunk)):
                    data[i + copy_to] = chunk[i]
        else:
            if RAND(2) == 1:
                value = RAND(256)
            else:
                value = data[RAND(len(data))]
            for i in range(copy_length):
                data[i + copy_to] = value
    return data


def havoc_perform_byte_seq_extra1(data):
    pass


def havoc_perform_byte_seq_extra2(data):
    pass


def havoc_splicing(data, files=None):
    if len(data) >= 2:
        for file in files:
            file_data = read_binary_file(file)
            if len(file_data) < 2:
                continue

            first_diff, last_diff = find_diffs(data, file_data)
            if last_diff < 2 or first_diff == last_diff:
                continue

            split_location = first_diff + RAND(last_diff - first_diff)

            data = array('B', data.tostring()[:split_location] + file_data[split_location:])
            # func(data.tostring())
            break

    return data


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
    log_redq("clearing dict %s" % repr(redqueen_dict))
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

    assert (len(redqueen_dict) == len(redqueen_addr_list))

    val = val[:16]
    for v in val.split("\0"):
        if len(v) > 3:
            if not addr in redqueen_dict:
                redqueen_dict[addr] = set()
                redqueen_addr_list.append(addr)
            # log_redq("Added Dynamic Dict: %s"%repr(v))
            redqueen_dict[addr].add(v)


def append_handler(handler):
    global havoc_handler
    havoc_handler.append(handler)


def apply_dict_to_data(data, entry, entry_pos):
    newdata = array('B', data.tostring()[:entry_pos] + entry + data.tostring()[entry_pos + len(entry):])
    # log_redq("HAVOC DICT: %s [%s] -> %s "%(repr(data.tostring()),repr(entry), repr(newdata.tostring())))
    return newdata


def havoc_dict(data):
    global redqueen_dict
    global dict_import

    has_redq = len(redqueen_dict) > 0
    has_dict = len(dict_import) > 0
    coin = RAND(2) != 0

    if has_redq and ((not has_dict) or coin):
        addr = redqueen_addr_list[RAND(len(redqueen_addr_list))]
        dict_values = list(redqueen_dict[addr])
        dict_entry = dict_values[RAND(len(dict_values))]
        entry_pos = RAND(max([0, len(data) - len(dict_entry)]))
        return apply_dict_to_data(data, dict_entry, entry_pos)

    if has_dict:
        dict_entry = dict_import[RAND(len(dict_import))]
        dict_entry = dict_entry[:len(data)]
        entry_pos = RAND(max([0, len(data) - len(dict_entry)]))
        return apply_dict_to_data(data, dict_entry, entry_pos)
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
                 havoc_dict

                 # havoc_perform_clone_random_byte,
                 # havoc_perform_byte_seq_override,
                 # havoc_perform_byte_seq_extra1,
                 # havoc_perform_byte_seq_extra2,
                 # havoc_insert_line,
                 ]
