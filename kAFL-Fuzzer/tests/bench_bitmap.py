#!/usr/bin/python3

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
##
# Src/Dst IPs of discovered basic blocks are probably highly biased.
# This script allows to test some different hash functions for mapping
# those discovered edges to a bitmap and measure collision rate for 
# different configurations.
# 
# The input is expected to be in kAFL trace file format:
#
# $ python3 tools/bitmap_test.py ~/workdir/traces/tracefile_sorted.uniq.gz
#
# Results: Looks like kAFL hash is already quite optimal. However, it seems
# that 64k bitmaps are too small except for simple test cases with <2000 edges.
##

import os
import sys

import time
import glob
import shutil
import msgpack
import gzip
import re
import mmh3

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)) + "/../kAFL-Fuzzer/")
from common.config import DebugConfiguration
from common.self_check import self_check, post_self_check
import common.color
from operator import itemgetter

from common.debug import log_debug, enable_logging
from common.util import prepare_working_dir, read_binary_file, print_note, print_fail, print_warning
from common.qemu import qemu

import json
import csv
    
global mod
mod = 65536  # 64k bitmap
mod = 131072 # 128k bitmap

global mask64
mask64 = 0xffffffffffffffff

class TraceParser:

    def __init__(self):
        self.known_bbs = set()
        self.known_edges = set()

    def djb(self, addr1, addr2, n):
        x = addr1
        y = addr2 

        h = 5381
        h = h*33 + (x & 0xff)
        h = h*33 + (x>>8 & 0xff)
        h = h*33 + (x>>16 & 0xff)
        h = h*33 + (x>>24 & 0xff)
        h = h*33 + (y & 0xff)
        h = h*33 + (y>>8 & 0xff)
        h = h*33 + (y>>16 & 0xff)
        h = h*33 + (y>>24 & 0xff)
        return h % mod

    def ror64(self, v, n):
        return (v >> n) | ((v << 64-n) & mask64)

    def rmxmix(self, v):
        C1 = 0x9FB21C651E98DF25
        v ^= (self.ror64(v,49) * C1) & mask64
        v ^= (self.ror64(v,24) * C1) & mask64
        v ^= (self.ror64(v,17) * C1) & mask64
        v ^= (self.ror64(v, 9) * C1) & mask64
        return (v ^ (v >> 27)) & mask64

    # http://mostlymangling.blogspot.com/2018/07/on-mixing-functions-in-fast-splittable.html
    def filter_rmxmix(self, addr1, addr2, n):
        v1 = self.rmxmix(addr1)
        v2 = self.rmxmix(addr2)
        return (v1 ^ v2 >> n) % mod

    def single_andshift(self, addr1, addr2, n):
        x = addr1 + (addr2 << n)
        y = addr1 ^ (addr2 << n)
        addr1  += y << 5
        addr1  ^= x >> 13
        addr1  ^= y << 3
        return addr1 % mod

    def single_xorshift(self, addr1, addr2, n):
        x = addr1 ^ (addr2 << n)
        addr1  ^= x << 9
        addr1  ^= x >> 13
        addr1  ^= x << 3
        return addr1 % mod

    def double_xorshift(self, addr1,addr2, n):
        x = addr1 ^ (addr2 << n)
        y = addr1 ^ (addr2 >> n)
        addr1  ^= x << 14
        addr1  ^= x >> 13
        addr1  ^= x << 15
        addr1  ^= y << 11
        addr1  ^= y >> 19
        addr1  ^= y << 8
        return addr1 % mod

    def afl_xorshift(self, addr1, addr2, n):
        return (addr1 ^ (addr2 >> n)) % mod

    def kafl_mix_bits(self, v): # designed to work on uint64_t
        v = (v ^ (v >> 31))          & mask64
        v = (v * 0x7fb5d329728ea185) & mask64
        v = (v ^ (v >> 27))          & mask64
        v = (v * 0x81dadef4bc2dd44d) & mask64
        v = (v ^ (v >> 33))          & mask64
        return v

    def kafl_twiddle(self, addr1,addr2, n):

        v1 = self.kafl_mix_bits(addr1)
        v2 = self.kafl_mix_bits(addr2)

        edge = (v1 ^ (v2 >> n)) & 0xffffff
        return edge % mod


    def edge_hash(self, addr1, addr2):
        # total edges: 2118
        #return mmh3.hash(addr1.to_bytes(4, byteorder='big') + 
        #                 addr2.to_bytes(4, byteorder='big')) % mod          # {1: 2066, 2: 26}

        #return self.filter_rmxmix(addr1, addr2, 3)                          # {1: 2060, 2: 29}
        #return self.single_andshift(addr1, addr2, 3)                        # {1: 2082, 2: 18}
        # return self.single_xorshift(addr1, addr2, 3)                        # {1: 2052, 2: 33}
        # return self.single_xorshift(addr1, addr2, 1)                        # {1: 2048, 2: 35}
        # return self.double_xorshift(addr1, addr2, 1)                        # {1: 2051, 2: 32, 3: 1}
        # return ((addr1 ^ addr2 >> 1) + addr1 ) % mod                        # {1: 1899, 2: 83, 3: 10, 4: 2, 5: 3}
        # return ((addr1 ^ addr2 >> 1) * 3 ^ addr1 ) % mod                    # {1: 2016, 2: 51}
        # return ((addr1 + 0xc17f8e3a) ^ (0x2e8a1e51 + (addr2 >> 1))) % mod   # {1: 2025, 2: 45, 3: 1}
        # return self.djb(addr1, addr2, 3)                                    # {1: 2018, 2: 50}
        # return self.afl_xorshift(addr1,addr2, 3)                            # {1: 2018, 2: 50}
        # return self.afl_xorshift(addr1,addr2, 1)                            # {1: 2044, 2: 34, 3: 2}  ## AFL ##
        return self.kafl_twiddle(addr1, addr2, 1)                           # {1: 2062, 2: 28}

    def parse_trace_file(self, trace_file):
        if not os.path.isfile(trace_file):
            print_note("Could not find trace file %s, skipping.." % trace_file)
            return None

        gaps = set()
        bbs = set()
        edges = set()
        bitmap = dict()

        with gzip.open(trace_file, 'rb') as f:
            #for line in f.readlines():
            #    info = (json.loads(line.decode()))
            #    if 'trace_enable' in info:
            #        gaps.add(info['trace_enable'])
            #    if 'edge' in info:
            #        edges.add("%s_%s" % (info['edge'][0], info['edge'][1]))
            #        bbs.add(info['edge'][0])
            #        bbs.add(info['edge'][1])
            # slightly faster than above line-wise json parsing
            for m in re.finditer("\{.(\w+).: \[?(\d+),?(\d+)?\]? \}", f.read().decode()):
                if m.group(1) == "trace_enable": 
                    gaps.add(m.group(2))
                if m.group(1) == "edge": 
                    edges.add("%s_%s" % (m.group(2), m.group(3)))

                    h = self.edge_hash(int(m.group(2)), int(m.group(3)))
                    if h not in bitmap:
                        bitmap[h] = set()
                    bitmap[h].add("%s_%s" % (m.group(2), m.group(3)))

                    bbs.add(m.group(2))
                    bbs.add(m.group(3))
            return {'bbs': bbs, 'edges': edges, 'gaps': gaps, 'bitmap': bitmap}

def main():
    trace_parser = TraceParser()
    bitmap = dict()

    for trace_file in sys.argv[1:]:
        findings = trace_parser.parse_trace_file(trace_file)
        if not findings: 
            print_note("No findings from trace %s?!" % trace_file)
        if len(findings['gaps']) > 1:
            print_note("Got multiple gaps in trace %s" % trace_file)

        bitmap.update(findings['bitmap'])

    bitmap_stats = dict()
    for i in bitmap:
        #print("%d: %s" % (i, repr(bitmap[i])))
        entries = len(bitmap[i])
        if entries not in bitmap_stats:
            bitmap_stats[entries] = 0
        bitmap_stats[entries] += 1

    edges = sum(bitmap_stats.values())

    TOTAL=6198
    print("Bitmap stats: " + repr(bitmap_stats))
    print("Lost %d out of %d edges (%.2f%%)" % (TOTAL-edges, TOTAL, 100*(TOTAL-edges)/TOTAL))
    print("Lost %d out of %d edges (%.2f%%)" % (2118-edges, 2118, 100*(2118-edges)/2118))
    print("Done.")


if __name__ == "__main__":
    main()
