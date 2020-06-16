# Copyright (C) 2019-2020 Intel Corporation
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Test kAFL deterministic mutations
"""

import os
import struct
from binascii import hexlify

from fuzzer.technique.interesting_values import *
from fuzzer.technique.arithmetic import *
from fuzzer.technique.bitflip import *
from fuzzer.technique.helper import *

from tests.helper import ham_distance, ham_weight

def generate_effector_map(length):
    eff_map = []
    for i in range(length):
        eff_map.append(random.choice([True, False]))
    return eff_map


def run_mutation(func, payloads, v=False):

    global calls
    skip_zero = False
    eff_map = None

    def verifier(outdata, label=None):
        global calls
        calls += 1
        if v:
            print("Outdata: ",hexlify(outdata))

    for payload in payloads:
        calls = 0
        if v:
            print("Payload: ",hexlify(payload))

        func(bytearray(payload), verifier, effector_map=eff_map, skip_null=skip_zero, verbose=v)

        if v:
            print("Performed %d mutations." % calls)


def assert_invariants(func, max_flipped_bits, payloads):

    def verifier(outdata, label=None):
        # each mutator has characteristic max number of bits it can flip
        assert(ham_distance(payload,outdata) <= max_flipped_bits), "Flipped too many bits?\n%s\n%s" % (hexlify(payload),hexlify(outdata))

    for payload in payloads:
        copy = bytearray(payload)
        for skip_null in [False, True]:
            for use_eff_map in [False, True]:

                if use_eff_map:
                    eff_map = generate_effector_map(len(payload))
                else:
                    eff_map = None

                func(copy, verifier, effector_map=eff_map, skip_null=skip_null)

                # mutators may work directly on payload but must restore changes on exit!
                assert(copy == payload)

def assert_bitflip_invariants(func, flipped_bits, loops, skips, payloads):

    global calls

    def verifier(outdata, label=None):
        global calls
        calls += 1
        # each mutator has characteristic max number of bits it can flip
        assert(ham_distance(payload,outdata) == flipped_bits), "Bitflips mismatch:\n%s\n%s" % (hexlify(payload),hexlify(outdata))
        return True, True

    for payload in payloads:
        copy = bytearray(payload)
        for skip_null in [False, True]:
            for use_eff_map in [False, True]:

                if use_eff_map:
                    eff_map = generate_effector_map(len(payload))
                else:
                    eff_map = None

                calls = 0
                func(copy, verifier, effector_map=eff_map, skip_null=skip_null)

                # mutators may work directly on payload but must restore changes on exit!
                assert(copy == payload)

                # number of bitflip calls is constant in standard case
                if not skip_null and not eff_map:
                    assert(calls == loops*len(payload)-skips)


def test_invariants(v=False):

    old=False
    verbose=False

    payloads = []
    for length in [range(0, 3), 16, 23, 33]:
        payloads.append(rand.bytes(32))

    if old:
        func_calls = [
            [mutate_seq_8_bit_arithmetic_array, 8],
            [mutate_seq_16_bit_arithmetic_array, 16],
            [mutate_seq_32_bit_arithmetic_array, 20],
            [mutate_seq_8_bit_interesting_array, 8],
            [mutate_seq_16_bit_interesting_array, 16],
            [mutate_seq_32_bit_interesting_array, 32]]
    else:
        func_calls = [
            [mutate_seq_8_bit_arithmetic, 8],
            [mutate_seq_16_bit_arithmetic, 16],
            [mutate_seq_32_bit_arithmetic, 20],
            [mutate_seq_8_bit_interesting, 8],
            [mutate_seq_16_bit_interesting, 16],
            [mutate_seq_32_bit_interesting, 32]]

    for func in func_calls:
        assert_invariants(func[0], func[1], payloads)

    # for bitflips we can also check the total number of calls
    if old:
        func_calls = [
                [mutate_seq_walking_bits_array, 1, 8, 0],
                [mutate_seq_two_walking_bits_array, 2, 8, 1],
                [mutate_seq_four_walking_bits_array, 4, 8, 3],
                [mutate_seq_walking_byte_array, 8, 1, 0],
                [mutate_seq_two_walking_bytes_array, 16, 1, 1],
                [mutate_seq_four_walking_bytes_array, 32, 1, 3]]
    else:
        func_calls = [
                [mutate_seq_walking_bits, 1, 8, 0],
                [mutate_seq_two_walking_bits, 2, 8, 1],
                [mutate_seq_four_walking_bits, 4, 8, 3],
                [mutate_seq_walking_byte, 8, 1, 0],
                [mutate_seq_two_walking_bytes, 16, 1, 1],
                [mutate_seq_four_walking_bytes, 32, 1, 3]]

    for func, bits, loops, skips in func_calls:
        assert_bitflip_invariants(func, bits, loops, skips, payloads)


def assert_func_num_calls(func, payload, expected_calls, v=False):

    global calls
    skip_zero = False
    calls = 0

    def verifier(outdata, label=None):
        global calls
        calls += 1
        if v:
            print("Outdata: ",hexlify(outdata))

    func(payload, verifier, effector_map=None, verbose=v)

    if v:
        print("calls: %d" % calls)

    assert(expected_calls == calls), "Expected %d, got %d calls for payload %s" % (expected_calls, calls, hexlify(payload))


def test_arith_8_calls():

    verbose=False
    old=False

    if old:
        func=mutate_seq_8_bit_arithmetic_array
    else:
        func=mutate_seq_8_bit_arithmetic

    payloads = [
            bytes([0]),
            bytes([0,0]),
            bytes([0,0,0]),
            bytes([0,0,0,0]),
            bytes([255]),
            bytes([255,255]),
            bytes([255,255,255]),
            bytes([128,128]),
            bytes([30,31])]

    for pld in payloads:
        loops = len(pld)
        ops = 2*(AFL_ARITH_MAX-1-6) # derived manually by review

        assert_func_num_calls(func, bytearray(pld), loops*ops, verbose)

def test_arith_16_calls():

    verbose=False
    old=False

    if old:
        func=mutate_seq_16_bit_arithmetic_array
    else:
        func=mutate_seq_16_bit_arithmetic

    payloads = [
            bytes([0]),
            bytes([0,0]),
            bytes([0,0,0]),
            bytes([0,0,0,0]),
            bytes([255]),
            bytes([255,255]),
            bytes([255,255,255])]

    for pld in payloads:
        loops = len(pld)-1
        ops = (AFL_ARITH_MAX-1)*2 # derived manually by review

        assert_func_num_calls(func, bytearray(pld), loops*ops, verbose)


def test_arith_32_calls():

    verbose=False
    old=False

    if old:
        func=mutate_seq_32_bit_arithmetic_array
    else:
        func=mutate_seq_32_bit_arithmetic

    payloads = [
            bytes([0]),
            bytes([0,0]),
            bytes([0,0,0]),
            bytes([0,0,0,0]),
            bytes([0,0,0,0,0]),
            bytes([0,0,0,0,0,0]),
            bytes([255]),
            bytes([255,255]),
            bytes([255,255,255]),
            bytes([255,255,255,255]),
            bytes([255,255,255,255,255])]

    for pld in payloads:

        if len(pld) < 3:
            loops = 0
        else:
            loops = len(pld)-3

        ops = (AFL_ARITH_MAX-1)*2 # derived manually by review

        assert_func_num_calls(func, bytearray(pld), loops*ops, verbose)

def test_int_8_calls():

    verbose=False
    old=False

    if old:
        func=mutate_seq_8_bit_interesting_array
    else:
        func=mutate_seq_8_bit_interesting

    payloads = [
            [bytes([0]), 2],
            [bytes([0,0]), 2],
            [bytes([0,0,0]), 2],
            [bytes([0,0,0,0]), 2],
            [bytes([255]), 3],
            [bytes([255,255]), 3],
            [bytes([255,255,255]), 3],
            [bytes([128,128]), 4],
            [bytes([32,32]), 3]]

    for pld,ops in payloads:
        loops = len(pld)
        assert_func_num_calls(func, bytearray(pld), loops*ops, verbose)

def test_int_16_calls():

    verbose=False
    old=False

    if old:
        func=mutate_seq_16_bit_interesting_array
    else:
        func=mutate_seq_16_bit_interesting

    payloads = [
            [bytes([0]), 0],
            [bytes([0,0]), 6],
            [bytes([0,0,0]), 6],
            [bytes([0,0,0,0]), 6],
            [bytes([255]), 0],
            [bytes([255,255]), 10],
            [bytes([255,255,255]), 10],
            [bytes([255,128]), 22],
            [bytes([255,128,128]), 23],
            [bytes([128,128]), 24],
            [bytes([32,32]), 26]]

    for pld,ops in payloads:
        loops = len(pld)-1

        assert_func_num_calls(func, bytearray(pld), loops*ops, verbose)


def test_int_32_calls():

    verbose=False
    old=False

    if old:
        func=mutate_seq_32_bit_interesting_array
    else:
        func=mutate_seq_32_bit_interesting

    payloads = [
            [bytes([0]), 0],
            [bytes([0,0]), 0],
            [bytes([0,0,0]), 0],
            [bytes([0,0,0,0]), 10],
            [bytes([255]), 0],
            [bytes([255,255]), 0],
            [bytes([255,255,255,255]), 26],
            [bytes([255,128]), 22],
            [bytes([255,128,128]), 23],
            [bytes([255,255,128,128]), 38],
            [bytes([128,128,128,128,128]), 44]]

    for pld,ops in payloads:
        loops = len(pld)-3
        if len(pld) < 3:
            loops = 0
        else:
            loops = len(pld)-3

        assert_func_num_calls(func, bytearray(pld), loops*ops, verbose)


import timeit
def deter_benchmark():

    verbose=False
    old=False
    payloads = [b'abcdefghijk']

    def bench_arith_8():
        test_mutate_8_arithmetic(True, verbose)
        test_mutate_8_arithmetic(False, verbose)

    def bench_arith_16():
        run_arith_16(True, verbose)
        bench_arith_16(False, verbose)

    def bench_arith_32():
        #test_mutate_32_arithmetic(True, verbose)
        test_mutate_32_arithmetic(False, verbose)

    def bench_int32():
        test_mutate_32_interesting(True, verbose)
        test_mutate_32_interesting(False, verbose)

    def bench_int16():
        run_mutation(mutate_seq_16_bit_interesting_array, payloads, v=False)
        #run_mutation(mutate_seq_16_bit_interesting, payloads, v=False)

    #time_arith8  = timeit.timeit(stmt=bench_arith_8, number=10000)
    #print("afl_arith_8  = %5.02fs" % time_arith8)

    #time_arith16 = timeit.timeit(stmt=bench_arith_16, number=1)
    #print("afl_arith_16 = %5.02fs" % time_arith16)

    #time_arith32 = timeit.timeit(stmt=bench_arith_32, number=900)
    #print("afl_arith_32 = %5.02fs" % time_arith32)

    time_int16 = timeit.timeit(stmt=bench_int16, number=5000)
    print("afl_int_16 = %5.02fs" % time_int16)

def deter_main():

    #deter_benchmark()
    #return

    verbose=True

    payloads = [b'\x00', b'abcdefghijk', bytes([0,1,2,3,4,5,6,7,8,9]), bytes([254,255,255,254,255,254,252])]
    #payloads = [b'abcdefghijk']
    #payloads = [b'\x00\x00']


    #run_mutation(mutate_seq_8_bit_arithmetic_array, payloads,v=verbose)
    #run_mutation(mutate_seq_8_bit_arithmetic, payloads,v=verbose)
    #run_mutation(mutate_seq_16_bit_arithmetic_array, payloads,v=verbose)
    #run_mutation(mutate_seq_16_bit_arithmetic, payloads,v=verbose)
    #run_mutation(mutate_seq_32_bit_arithmetic_array, payloads,v=verbose)
    #run_mutation(mutate_seq_32_bit_arithmetic, payloads,v=verbose)

    #run_mutation(mutate_seq_8_bit_interesting_array, payloads,v=verbose)
    #run_mutation(mutate_seq_8_bit_interesting, payloads,v=verbose)
    #run_mutation(mutate_seq_16_bit_interesting_array, payloads, v=verbose)
    #run_mutation(mutate_seq_16_bit_interesting, payloads, v=verbose)
    #run_mutation(mutate_seq_32_bit_interesting_array, payloads, v=verbose)
    #run_mutation(mutate_seq_32_bit_interesting, payloads, v=verbose)

    #test_invariables()
    #test_arith_8_calls()
    #test_arith_16_calls()
    #test_arith_32_calls()
    #test_int_8_calls()
    test_int_16_calls()
    test_int_32_calls()


