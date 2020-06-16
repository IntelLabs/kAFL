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

import struct
from itertools import product


class Encoding:
    def to_intval(self, cmp, val):
        unpack_keys = {1: "B", 2: "H", 4: "L", 8: "Q"}
        key = unpack_keys.get(cmp.size / 8, None)
        if key:
            if self.signed:
                return struct.unpack("<" + key.lower(), val)[0]
            else:
                return struct.unpack("<" + key, val)[0]
        assert (false)

    def apply_reverse(self, val):
        if self.reverse:
            return val[::-1]
        return val

    def rev_desc(self):
        if self.reverse:
            return "r"
        return "p"

    def size(self):
        return 1

    def is_redundant(self, cmp, lhs, rhs):
        return False


class SextEncoding(Encoding):
    def __init__(self, bytes, reverse):
        self.bytes = bytes
        self.reverse = reverse

    @staticmethod
    def _is_applicable_sext(cmp, size_bytes, val):
        check_size = cmp.size > 8 * size_bytes
        head, tail = val[0:len(val) - size_bytes], val[len(val) - size_bytes:]
        check_zeros = head == "\0" * len(head) and ord(tail[0]) & 0x80 == 0
        check_ffs = head == "\xff" * len(head) and ord(tail[0]) & 0x80 != 1
        return check_size and (check_zeros or check_ffs)

    def is_applicable(self, cmp, lhs, rhs):
        if cmp.type == "STR":
            return False
        lhs = self.apply_reverse(lhs)
        rhs = self.apply_reverse(rhs)
        return SextEncoding._is_applicable_sext(cmp, self.bytes, lhs) and SextEncoding._is_applicable_sext(cmp,
                                                                                                           self.bytes,
                                                                                                           rhs)

    def encode(self, cmp, val):
        return [val[len(val) - self.bytes:len(val)]]

    def name(self):
        return "sext_%s_%d" % (self.rev_desc(), self.bytes)

    # def is_redundant(self, cmp, lhs, rhs):
    #    lhs = self.apply_reverse(lhs)
    #    rhs = self.apply_reverse(rhs)
    #    return not (ZextEncoding._is_applicable_zext(cmp,self.bytes, lhs) and ZextEncoding._is_applicable_zext(cmp, self.bytes, rhs))


class ZextEncoding(Encoding):
    def __init__(self, bytes, reverse):
        self.bytes = bytes
        self.reverse = reverse

    @staticmethod
    def _is_applicable_zext(cmp, size_bytes, val):
        return cmp.size > 8 * size_bytes and val[0:len(val) - size_bytes] == "\0" * (len(val) - size_bytes)

    def is_applicable(self, cmp, lhs, rhs):
        if cmp.type == "STR":
            return False
        lhs = self.apply_reverse(lhs)
        rhs = self.apply_reverse(rhs)
        return ZextEncoding._is_applicable_zext(cmp, self.bytes, lhs) and ZextEncoding._is_applicable_zext(cmp,
                                                                                                           self.bytes,
                                                                                                           rhs)

    # def is_redundant(self, cmp, lhs, rhs):
    #    if self.bytes > 1:
    #        lhs = self.apply_reverse(lhs)
    #        rhs = self.apply_reverse(rhs)
    #        return not (ZextEncoding._is_applicable_zext(cmp,self.bytes/2, lhs) and ZextEncoding._is_applicable_zext(cmp, self.bytes/2, rhs))
    #    return False

    def encode(self, cmp, val):
        return [val[len(val) - self.bytes:len(val)]]

    def name(self):
        return "zext_%s_%d" % (self.rev_desc(), self.bytes)


class AsciiEncoding(Encoding):
    def __init__(self, base, signed):
        self.base = base
        self.signed = signed

    def is_applicable(self, cmp, lhs, rhs):
        return cmp.type != "STR"

    def encode(self, cmp, val):
        intval = self.to_intval(cmp, val)
        if self.base == 16:
            return ["%x" % intval]
        if self.base == 10:
            return ["%d" % intval]
        if self.base == 8:
            return ["%o" % intval]
        assert (False)

    def name(self):
        sign = "u"
        if self.signed:
            sign = "s"
        return "ascii_%s_%d" % (sign, self.base)


class MemEncoding(Encoding):
    def __init__(self, length):
        self.length = length

    def is_applicable(self, cmp, lhs, rhs):
        if lhs[0:self.length].count("\0") > self.length / 2 or rhs[0:self.length].count("\0") > self.length / 2:
            return False
        return cmp.type == "STR"

    def encode(self, cmp, val):
        return [val[0:self.length]]

    def name(self):
        return "mem_%d" % (self.length)


class CStringEncoding(Encoding):

    def is_applicable(self, cmp, lhs, rhs):
        if len(lhs) < 2 or len(rhs) < 2:
            return False
        non_null1 = lhs[0] != "\0" and rhs[0] != "\0"
        non_null2 = lhs[1] != "\0" and rhs[1] != "\0"
        return cmp.type == "STR" and non_null1 and non_null2

    def encode(self, cmp, val):
        if "\0" in val:
            return [val[0:max(2, val.find("\0"))]]
        else:
            return [val]

    def name(self):
        return "cstr"


class CStrChrEncoding(Encoding):

    def __init__(self, amount=0):
        self.amount = amount

    def is_applicable(self, cmp, lhs, rhs):
        if len(lhs) <= self.amount or len(rhs) < 2:
            return False
        non_null2 = rhs[0] != "\0" and rhs[1:] == "\0" * (len(rhs) - 1)
        return cmp.type == "STR" and non_null2

    def encode(self, cmp, val):
        if val[1] == "\0" and val[0] != "\0":
            return val[0]
        return val[self.amount]

    def name(self):
        return "cstrchr_%d" % self.amount


class PlainEncoding(Encoding):
    def __init__(self, reverse):
        self.reverse = reverse

    def is_applicable(self, cmp, lhs, rhs):
        return cmp.type != "STR"

    def encode(self, cmp, val):
        return [self.apply_reverse(val)]

    # def is_redundant(self, cmp, lhs, rhs):
    #    if cmp.type == "STR":
    #        return False
    #    lhs = self.apply_reverse(lhs)
    #    rhs = self.apply_reverse(rhs)
    #    return ZextEncoding._is_applicable_zext(cmp, cmp.size*4, lhs) and ZextEncoding._is_applicable_zext(cmp, cmp.size*4, rhs)

    def name(self):
        return "plain_%s" % (self.rev_desc())


class SplitEncoding(Encoding):
    def __init__(self, len, reverse):
        assert (len == 8)
        self.reverse = reverse

    def is_applicable(self, cmp, lhs, rhs):
        return cmp.size == 64

    def encode(self, cmp, val):
        val = self.apply_reverse(val)
        return [val[0:4], val[4:8]]

    def name(self):
        return "split_%s" % (self.rev_desc())

    def size(self):
        return 2

    def is_redundant(self, cmp, lhs, rhs):
        # unhandled corner case: split where 00000000 is split in uncolorized version, but colorized version is actually
        # informative
        zeros = "\0\0\0\0"
        low = (lhs[:4] == zeros and rhs[:4] == zeros)
        high = (lhs[4:] == zeros and rhs[4:] == zeros)
        # log_redq("is redundant %s %s %s %s"%(lhs, rhs, low, high))
        return low or high


class R1E(Encoding):
    def __init__(self, orig):
        self.orig = orig

    def is_applicable(self, cmp, lhs, rhs):
        res = self.orig.is_applicable(cmp, lhs, rhs)
        # if cmp.addr == 4196216:
        #    print(repr(("is_applicable", cmp.addr,lhs, rhs, "=", res)))
        return res

    def encode(self, cmp, val):
        res = map(self.r1, self.orig.encode(cmp, val))
        # if cmp.addr == 4196216:
        #    print(repr(("encode",val,"to",res)))
        return res

    def name(self):
        return "R1(%s)" % self.orig.name()

    def r1(self, str):
        return "".join(map(lambda x: chr((ord(x) + 1) % 256), str))


Encoders = [ZextEncoding(bytes, reverse) for (bytes, reverse) in product([1, 2, 4], [True, False])] + \
           [SextEncoding(bytes, reverse) for (bytes, reverse) in product([1, 2, 4], [True, False])] + \
           [AsciiEncoding(base, signed) for (base, signed) in product([8, 10, 16], [True, False])] + \
           [PlainEncoding(True), PlainEncoding(False)] + \
           [SplitEncoding(8, True), SplitEncoding(8, False)] + \
           [CStringEncoding()] + \
           [MemEncoding(length) for length in [4, 5, 6, 7, 8, 16, 32]]  # +\
# [ R1E(ZextEncoding(bytes, reverse)) for (bytes, reverse) in product([4], [True, False]) ] + \
# [ R1E(SextEncoding(bytes, reverse)) for (bytes, reverse) in product([4], [True, False]) ] + \
# [ R1E(PlainEncoding(True)), R1E(PlainEncoding(False)) ] + \
# [ R1E(CStringEncoding()) ] + \
# [ R1E(MemEncoding(length)) for length in [4, 5, 6, 7, 8, 16, 32] ]  # +\
# [ CStrChrEncoding(length) for length in xrange(0,4)]

# Encoders =  [ CStrChrEncoding(length) for length in xrange(0,4)]

import unittest


class Dummy:
    pass


class TestEncoder(unittest.TestCase):
    def test_applicable(self):
        a = Dummy()
        a.size = 32
        assert (Encoding.is_applicable(a, "p_zext1", "\0\0\0a"))
        assert (not Encoding.is_applicable(a, "p_zext1", "\0\0ba"))
        assert (not Encoding.is_applicable(a, "r_zext1", "\0\0\0a"))
        assert (Encoding.is_applicable(a, "r_zext1", "\0\0\0a"))


if __name__ == '__main__':
    unittest.main()
