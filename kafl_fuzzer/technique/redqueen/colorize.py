# Copyright (C) 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright (C) 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Redqueen Input Colorizer
"""

import array

from kafl_fuzzer.common import rand


# definition of range indicies:
# array = [a,b,c,d]
# the range (0,0) contains no element
# the range (0,1) contains exactly the element a
# the amount of elements in a range is max_-min_

class ColorizerStrategy:
    COLORABLE = 1
    UNKNOWN = 0
    FIXED = -1

    def __init__(self, data_length, checker):
        self.color_info = array.array('b', [self.UNKNOWN for _ in range(0, data_length)])
        self.unknown_ranges = set()
        if data_length > 0:
            self.add_unknown_range(0, data_length)
        self.checker = checker

    def is_range_colorable(self, min_, max_):
        if self.checker(min_, max_):
            for i in range(min_, max_):
                self.color_info[i] = self.COLORABLE
            return True
        else:
            if min_ + 1 == max_:
                self.color_info[min_] = self.FIXED
            return False

    def bin_search(self, min_, max_):
        if self.is_range_colorable(min_, max_) or min_ + 1 == max_:
            return
        center = int(min_ + (max_ - min_) / 2)
        self.add_unknown_range(min_, center)
        self.add_unknown_range(center, max_)

    def colorize_step(self):
        (min_i, max_i) = max(self.unknown_ranges, key=lambda mi_ma: mi_ma[1] - mi_ma[0])
        self.unknown_ranges.remove((min_i, max_i))
        self.bin_search(min_i, max_i)

    def add_unknown_range(self, min_, max_):
        assert (min_ < max_)
        self.unknown_ranges.add((min_, max_))


import unittest
import random

def check(min_, max_, array):
    res = all([array[i] == 0 for i in range(min_, max_)])
    return res


def check_nondet(min_, max_, array):
    res = all([array[i] == 0 for i in range(min_, max_)])
    if random.randint(0, 100) < 10:
        return False
    return res


class TestColorizer(unittest.TestCase):

    def check_fuzz_result(self, i, testcase):
        color_info = [0] * len(testcase)
        c = ColorizerStrategy(len(testcase), lambda min_, max_: check(min_, max_, testcase))
        while len(c.unknown_ranges) > 0:
            # print c.unknown_ranges
            c.colorize_step()
        print("det:", c.color_info)
        self.assertEqual([(0 if x == 1 else 1) for x in c.color_info], testcase)
        assert (all([x != 0 for x in c.color_info]))

    def check_nondet_fuzz_result(self, i, testcase):
        color_info = [0] * len(testcase)
        c = ColorizerStrategy(len(testcase), lambda min_, max_: check_nondet(min_, max_, testcase))
        while len(c.unknown_ranges) > 0:
            offset = c.colorize_step()
        print("nondet:", c.color_info)
        if not all([x != 0 for x in c.color_info]):
            assert (False)

    def test_colorize_step_fuzzed(self):
        self.check_fuzz_result(1, [0])
        self.check_fuzz_result(1, [0, 0, 1, 0])
        self.check_fuzz_result(0, [0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 1, 0, 1])

    def test_fuzz_colorize_step(self):
        for i in range(0, 1000):
            random.seed(i)
            tlen = random.randint(1, 40)
            testcase = [0] * tlen
            num_ones = random.randint(0, (tlen - 1))
            while num_ones > 0:
                r = random.randint(0, tlen - 1)
                if testcase[r] == 0:
                    testcase[r] = 1
                    num_ones -= 1
            print("testcase", testcase)
            self.check_fuzz_result(i, testcase)
            self.check_nondet_fuzz_result(i, testcase)


if __name__ == '__main__':
    unittest.main()
