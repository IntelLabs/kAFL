#!/usr/bin/python3
#
# based on https://gist.github.com/cactus/4073659
# Test compression speed to avoid delays in Master sync
#

import timeit
import lz4.frame
#import lzf
import zlib
import snappy
import os
import sys
from timeit import Timer


sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)) + "/../kAFL-Fuzzer/")
from common.util import read_binary_file, print_note, print_fail, print_warning, atomic_write

DATA = open("compression_test.py", "rb").read()
DLEN = len(DATA)
LZ4_DATA = lz4.frame.compress(DATA)
SNAPPY_DATA = snappy.compress(DATA)
#LZF_DATA = lzf.compress(DATA)
ZLIB_DATA = zlib.compress(DATA)
LOOPS = 100000

print("Data Size:")
print("  Input:  %4d" %          len(DATA))
print("  LZ4:    %4d (%.2f)" %   (len(LZ4_DATA), len(LZ4_DATA) / float(len(DATA))))
print("  Snappy: %4d (%.2f)" %   (len(SNAPPY_DATA), len(SNAPPY_DATA) / float(len(DATA))))
#print("  LZF:    %4d (%.2f)" %   (len(LZF_DATA), len(LZF_DATA) / float(len(DATA))))
print("  ZLIB:   %4d (%.2f)" %   (len(ZLIB_DATA), len(ZLIB_DATA) / float(len(DATA))))
#print("  LZ4 / Snappy: %f" %    (float(len(LZ4_DATA)) / float(len(SNAPPY_DATA))))
#print("  LZ4 / LZF:    %f" %       (float(len(LZ4_DATA)) / float(len(LZF_DATA))))
#print("  LZ4 / ZLIB:   %f" %      (float(len(LZ4_DATA)) / float(len(ZLIB_DATA))))


print("Benchmark: %d calls" %  LOOPS)
print("  ZLIB   Compression: %fs"   % Timer("zlib.compress(DATA)", "from __main__ import DATA; import zlib").timeit(number=LOOPS))
print("  Snappy Compression: %fs"   % Timer("snappy.compress(DATA)", "from __main__ import DATA; import snappy").timeit(number=LOOPS))
#print("  LZF    Compression: %fs"   % Timer("lzf.compress(DATA)", "from __main__ import DATA; import lzf").timeit(number=LOOPS))
print("  LZ4    Compression: %fs"   % Timer("lz4.frame.compress(DATA)", "from __main__ import DATA; import lz4").timeit(number=LOOPS))
print("")
print("  ZLIB   Decompression: %fs" % Timer("zlib.decompress(ZLIB_DATA)", "from __main__ import ZLIB_DATA; import zlib").timeit(number=LOOPS))
#print("  LZF    Decompression: %fs" % Timer("lzf.decompress(LZF_DATA, DLEN)", "from __main__ import LZF_DATA,DLEN; import lzf").timeit(number=LOOPS))
print("  Snappy Decompression: %fs" % Timer("snappy.uncompress(SNAPPY_DATA)", "from __main__ import SNAPPY_DATA; import snappy").timeit(number=LOOPS))
print("  LZ4    Decompression: %fs" % Timer("lz4.frame.decompress(LZ4_DATA)", "from __main__ import LZ4_DATA; import lz4").timeit(number=LOOPS))



