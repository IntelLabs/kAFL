# Copyright (C) 2019-2020 Intel Corporation
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Test kAFL havoc mutations
"""

import unittest, os
import struct
from binascii import hexlify

from fuzzer.technique.havoc_handler import *
from fuzzer.technique.helper import *

from tests.helper import ham_distance, ham_weight

EMPTY_DICT = {}
EMPTY_ARRAY = []

ITERATIONS=2*1024

def test_redqueen_dict_clear():
    clear_redqueen_dict()
    assert(EMPTY_DICT == get_redqueen_dict()), "Failed to clear RQ dict!"

def test_redqueen_dict_add():
    MY_DICT = {23: b'ABCD', 42: b'1234'}

    clear_redqueen_dict()

    for addr in MY_DICT:
        add_to_redqueen_dict(addr, MY_DICT[addr])

    # dupes should be dropped!
    add_to_redqueen_dict(23, MY_DICT[23])

    rq_dict = get_redqueen_dict()
    for addr in MY_DICT:
        assert(MY_DICT[addr] in rq_dict[addr]), "Mismatching elements in RQ dict!"

def test_havoc_bit_flip():

    for _ in range(ITERATIONS):

        assert(b'' == havoc_perform_bit_flip(b'')), "Failed on short input!"

        db = [b'1', b'123134', b'adfakh\0adfkn\x23']
        for data_in in db:
            data_out = havoc_perform_bit_flip(data_in)
            #print("Test Bitflip:", data_in, "=>", data_out)
            assert(len(data_in) == len(data_out)), "Returned length mismatch!"
            assert(1 == ham_distance(data_in, data_out)), "Bitflip flipped wrong bits!"

def test_havoc_interesting_value_8():

    for _ in range(ITERATIONS):

        assert(b'' == havoc_perform_insert_interesting_value_8(b'')), "Failed on short input!"

        db = [b'1', b'123134', b'adfakh\0adfkn\x23']
        for data_in in db:
            data_out = havoc_perform_insert_interesting_value_8(data_in)

            #print('Test Interesting 8-Bit:', hexlify(data_in), "=>", hexlify(data_out))
            assert(len(data_in) == len(data_out)), "Returned length mismatch!"
            assert(8 >= ham_distance(data_in, data_out)), "Flipped too many bits!"

            success=False
            for i in interesting_8_Bit:
                if struct.pack("!b",i) in bytearray(data_out):
                    success=True
            assert(success), "Bitflip flipped wrong bits!"

def test_havoc_interesting_value_16():

    for _ in range(ITERATIONS):

        assert(b'' == havoc_perform_insert_interesting_value_16(b'')), "Failed on short input!"
        assert(b'\x23' == havoc_perform_insert_interesting_value_16(b'\x23')), "Failed on short input!"

        db = [b'42', b'123134', b'adfakh\0adfkn\x23', b'!#@$%^&*']
        for data_in in db:
            data_out = havoc_perform_insert_interesting_value_16(data_in)

            #print('Test Interesting 16-Bit:', hexlify(data_in), "=>", hexlify(data_out))
            assert(len(data_in) == len(data_out)), "Returned length mismatch!"
            assert(16 >= ham_distance(data_in, data_out)), "Flipped too many bits!"

            success=False
            for i in interesting_16_Bit:
                if struct.pack("<h",i) in bytearray(data_out) or struct.pack(">h",i) in bytearray(data_out):
                    success=True
            assert(success), "Bitflip flipped wrong bits!"

def test_havoc_interesting_value_32():

    for _ in range(ITERATIONS):

        assert(b'' == havoc_perform_insert_interesting_value_32(b'')), "Failed on short input!"
        assert(b'\x23' == havoc_perform_insert_interesting_value_32(b'\x23')), "Failed on short input!"
        assert(b'\x23ab' == havoc_perform_insert_interesting_value_32(b'\x23ab')), "Failed on short input!"

        db = [b'42ab', b'123134acd', b'adf23akh\0adfkn\x23', b'!#@$%^&*']
        for data_in in db:
            data_out = havoc_perform_insert_interesting_value_32(data_in)

            #print('Test Interesting 32-Bit:', hexlify(data_in), "=>", hexlify(data_out))
            assert(len(data_in) == len(data_out)), "Returned bad length!"
            assert(32 >= ham_distance(data_in, data_out)), "Flipped too many bits!"

            success=False
            for i in interesting_32_Bit:
                if struct.pack("<i",i) in bytearray(data_out) or struct.pack(">i",i) in bytearray(data_out):
                    success=True
            assert(success), "Bitflip flipped wrong bits!"

def test_havoc_insert_line(v=False):

        db = [b'42ab', b'123134acd', b'adf23akh\0adfkn\x23', b'!#@$%^&*']

        for data_in in db:
            if v:
                print("In-data: %s" % hexlify(data_in))
            data_out = havoc_insert_line(data_in)

        if v:
            print("Outdata: %s" % hexlify(data_out))


def havoc_main():

    return

    test_redqueen_dict_clear()
    test_redqueen_dict_add()

    test_havoc_bit_flip()
    test_havoc_interesting_value_8()
    test_havoc_interesting_value_16()
    test_havoc_interesting_value_32()

    test_havoc_insert_line(v=True)

    print("All tests passed!")
