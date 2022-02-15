# Copyright (C) 2019-2020 Intel Corporation
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Test kAFL rand() wrapper / coin toss
"""

import random
import fastrand
from fuzzer.technique.helper import rand


def get_int_bitmap(limit, samples):

    elements = limit
    bitmap = [0 for _ in range(elements)]

    for _ in range(samples*elements):
        val = rand.int(limit)
        bitmap[val] += 1

    return bitmap


def test_rand_int():

    limits = [1, 2, 4, 7, 13, 17, 20, 32, 50, 100]
    samples = 5000

    for limit in limits:
        bitmap = get_int_bitmap(limit, samples)

        assert(bitmap[0] != 0), "rand.int() not spanning complete range?"
        assert(bitmap[-1] != 0), "rand.int() not spanning complete range?"

        for idx in range(len(bitmap)):
            bias = abs(1-bitmap[idx]/samples)
            assert(bias < 0.05), "rand.int() detected bias at bitmap[%d]=%f - need more samples?" % (idx,bias)


def get_select_bitmap(elements, samples):

    array = [x for x in range(elements)]
    bitmap = [0 for _ in range(elements)]

    for _ in range(samples*elements):
        val = rand.select(array)
        bitmap[val] += 1

    return bitmap


def get_gauss_sum(array, samples):

    # gauss sum over range(1...n)
    expect = 0.5*array[-1]*(array[-1]+1)

    # random sampled counting should arrive at similar result
    count = 0
    for _ in range(samples*len(array)):
        count += rand.select(array)

    real = count/samples
    return expect, real


def test_rand_select():

    samples = 5000
    elements = [1, 2, 17, 64]

    for element in elements:
        bitmap = get_select_bitmap(element, samples)

        assert(bitmap[0] != 0), "rand.select() not spanning complete range?"
        assert(bitmap[-1] != 0), "rand.select() not spanning complete range?"

        for idx in range(len(bitmap)):
            bias = abs(1-bitmap[idx]/samples)
            assert(bias < 0.1), "rand.select() detected bias at bitmap[%d]=%f - need more samples?" % (idx,bias)

    for limit in elements:
        array = [i for i in range(limit)]
        expect, real = get_gauss_sum(array, samples)

        assert(abs(expect-real)/100 < 0.1), "Gauss Sum mismatch: %d != %d" % (expect, real)


def get_bytes_bitmap(length, samples):

    elements = 256
    bitmap = [0 for _ in range(elements)]

    for _ in range(samples):
        array = rand.bytes(length)
        for byte in array:
            bitmap[byte] += 1

    return bitmap


def test_rand_bytes():

    lengths = [1, 3, 32, 17, 64]

    for length in lengths:
        bitmap = get_bytes_bitmap(length, 1)

        total = 0
        for count in bitmap:
            total += count

        assert(total == length), "rand.bytes() returned unexpected length"

    # similar to shuffled gauss count we can expect a random 256 byte array to include each value about once..
    length=256
    samples = 100
    byte_array = rand.bytes(length)
    _, real = get_gauss_sum(byte_array, samples)

    n = 255
    expect = n/2*(n+1)

    assert(abs(real/samples / expect) < 0.1), "rand.bytes() bias detected, gauss count: %d != %d" % (real/samples,expect)


def test_coin_semantics():

    samples = 1000

    check = 0
    for _ in range(samples):
        if rand.int(2) == 0: # chance 1 out of 2
            check += 1
    real = check/samples

    assert(abs(check/samples - 1/2) < 0.1), "Coin toss bias - semantics mismatch?"

    check = 0
    for _ in range(samples):
        if rand.int(4) == 0: # chance 1 out of 4
            check += 1
    
    assert(abs(check/samples - 1/4) < 0.1), "Coin toss bias - semantics mismatch?"

    check = 0
    for _ in range(samples):
        if rand.int(100) < 20: # 20%
            check += 1

    assert(abs(check/samples - 0.2) < 0.1), "Coin toss bias - semantics mismatch?"

    check = 0
    for _ in range(samples):
        if rand.int(2) == 0:
            if rand.int(4) == 0:
                pass
            else:
                check += 1 # 3/4 * 1/2

    assert(abs(check/samples - 3/4*1/2) < 0.1), "Coin toss bias - semantics mismatch?"

def bench_randint():

    data = bytearray()
    selection = bytearray()
    for i in range(2048):
        data += bytes([rand.int(256)])
        #data += bytes([fastrand.pcg32bounded(256)])

    num=256
    for i in range(num):
        selection += bytes([rand.select(data)])
    assert(len(selection) == num)

def bench_randomint():

    data = bytearray()
    selection = bytearray()
    for i in range(2048):
        data += bytes([random.randint(0,255)])

    num=256
    for i in range(num):
        selection += bytes([random.choice(data)])
    assert(len(selection) == num)

import timeit
def rand_benchmark():

    ## simple benchmark to check if rand.int() is really faster..
    #time_int = timeit.timeit(stmt=test_rand_int, number=10)
    #print("rand_int()    = %5.02fs" % time_int)

    #time_coin = timeit.timeit(stmt=test_coin_semantics, number=2000)
    #print("rand_coin()   = %5.02fs" % time_coin)

    #time_sel = timeit.timeit(stmt=test_rand_select, number=10)
    #print("rand_select() = %5.02fs" % time_sel)

    time_rand = timeit.timeit(stmt=bench_randint, number=1000)
    print("bench_rand.int() = %5.02fs" % time_rand)

    time_random = timeit.timeit(stmt=bench_randomint, number=1000)
    print("bench_random.int() = %5.02fs" % time_random)

def rand_main():
    #test_coin_semantics()
    rand_benchmark()
