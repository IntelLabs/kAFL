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

import itertools
import re
import struct

import fuzzer
from common.debug import log_redq
from encoding import Encoders
from fuzzer.technique import havoc_handler

MAX_NUMBER_PERMUTATIONS = 256  # number of trials per address, lhs and encoding

HAMMER_LEA = False
known_lea_offsets = set()


def enable_hammering():
    global HAMMER_LEA
    log_redq("Hammering enabled!")
    HAMMER_LEA = True


class Cmp:
    def __init__(self, addr, type, size, is_imm):
        self.addr = addr
        self.type = type
        self.size = size
        self.is_imm = is_imm

        self.run_info_to_pairs = {}
        self.enc_and_val_to_encval = {}
        self.run_infos_with_not_all_found = {}
        self.original_rhs = set()
        self.original_lhs = set()
        self.colored_rhs = set()
        self.colored_lhs = set()
        self.num_mutations = None
        self.hammer = (not self.addr in known_lea_offsets) and (self.type in ["LEA", "SUB", "ADD"])
        known_lea_offsets.add(self.addr)
        self.offsets_and_lhs_to_rhs = {}
        index = None

    def add_result(self, run_info, lhs, rhs):
        self.run_info_to_pairs[run_info] = self.run_info_to_pairs.get(run_info, set())
        if run_info.was_colored:
            self.colored_lhs.add(lhs)
            self.colored_rhs.add(rhs)
            self.run_info_to_pairs[run_info].add((lhs, rhs))
        else:
            if not self.is_simple_mutation(lhs, rhs):
                self.original_lhs.add(lhs)
                self.original_rhs.add(rhs)
                self.run_info_to_pairs[run_info].add((lhs, rhs))

    def is_simple_mutation(self, lhs, rhs):
        if lhs == rhs:
            return True
        if self.type == "STR":
            return False
        else:
            unpack_keys = {1: "B", 2: "H", 4: "L", 8: "Q"}
            bytes = self.size / 8
            key = unpack_keys.get(bytes, None)
            ilhs = struct.unpack(">" + key, lhs)[0]
            irhs = struct.unpack(">" + key, rhs)[0]
            if abs(ilhs - irhs) < fuzzer.technique.helper.AFL_ARITH_MAX:
                return True
            if lhs == "\0" * bytes:
                return True
        return False

    def was_true_in(self, run_info):
        # print self.run_info_to_results[run_info]
        # log_redq("check if cmp was satisfied: %s"%repr(self.run_info_to_pairs[run_info]))
        return all([lhs == rhs for (lhs, rhs) in self.run_info_to_pairs[run_info]])

    def __calc_available_encoders(self):
        for enc in Encoders:
            if all([self.__is_valid_encoder_for(enc, run_info) for run_info in self.run_info_to_pairs]):
                yield (enc)

    def __is_valid_encoder_for(self, enc, run_info):
        for (lhs, rhs) in self.run_info_to_pairs[run_info]:
            if not enc.is_applicable(self, lhs, rhs):
                return False
        return True

    def calc_mutations(self, orig_run_info, num_runs):
        self.num_mutations = 0
        for enc in self.__calc_available_encoders():
            cmp_encoded = CmpEncoded(self, enc)
            if cmp_encoded.is_interessting(orig_run_info, num_runs):
                for (offsets, lhs, rhs) in cmp_encoded.get_mutations(orig_run_info):
                    self.num_mutations += 1
                    yield (offsets, lhs, rhs, enc)

    def could_be_hash(self):
        # log_redq("Got cmp @ %x could be hash?"%self.addr)
        # log_redq("orig_lhs \t%s"%repr(self.original_lhs))
        # log_redq("colo_lhs\t%s"%repr(self.colored_lhs))

        # log_redq("orig_rhs \t%s"%repr(self.original_rhs))
        # log_redq("colo_rhs\t%s"%repr(self.colored_rhs))
        # assert(self.num_mutations != None)
        if not self.num_mutations or self.num_mutations > 16:
            return False
        if self.is_imm or self.type != "CMP" or not self.size > 8:
            return False
        if len(self.original_lhs) > 32:
            return False
        if self.original_lhs == self.colored_lhs and self.original_rhs == self.colored_rhs:
            return False
        if all([lhs.count("\0") > 0 for lhs in self.original_lhs]) and all(
                [lhs.count("\0") > 0 for lhs in self.original_lhs]):
            return False
        # log_redq("Got cmp @ %x could be hash?"%self.addr)
        # log_redq("orig_lhs \t%s"%repr(self.original_lhs))
        # log_redq("colo_lhs\t%s"%repr(self.colored_lhs))

        # log_redq("orig_rhs \t%s"%repr(self.original_rhs))
        # log_redq("colo_rhs\t%s"%repr(self.colored_rhs))
        return True


class CmpEncoded:
    def __init__(self, cmp, encoding):
        self.cmp = cmp
        self.enc = encoding
        self.occured_in_all_run_infos = True
        self.mutations = None
        self.all_valid_offsets = None
        self.val_to_encval = {}

    def __get_encoded(self, val):
        if (val) in self.val_to_encval:
            return self.val_to_encval[val]
        encval = self.enc.encode(self.cmp, val)
        self.val_to_encval[val] = encval
        return encval

    def __restrict_offset_tuple(self, offset_tuple, orig_run_info):
        res = list(offset_tuple)
        valid_offsets = self.get_offset_intersect_tuple(orig_run_info)
        if valid_offsets != None:
            for i in xrange(len(offset_tuple)):
                res[i] &= valid_offsets[i]
        else:
            assert (len(self.cmp.run_info_to_pairs) == 1)
        return res

    def get_offset_intersect_tuple(self, orig_info):
        if self.all_valid_offsets:
            return self.all_valid_offsets
        for run_info in self.cmp.run_info_to_pairs:
            if run_info != orig_info:
                if not self.all_valid_offsets:
                    self.all_valid_offsets = self.get_offset_union_tuple(run_info)
                else:
                    other_offsets = self.get_offset_union_tuple(run_info)
                    for i in xrange(len(self.all_valid_offsets)):
                        self.all_valid_offsets[i] &= other_offets[i]
        return self.all_valid_offsets

    def get_offset_union_tuple(self, run_info):
        union_tuple = [set() for _ in xrange(self.enc.size())]
        set_of_lhs = set()
        for (lhs, rhs) in self.cmp.run_info_to_pairs[run_info]:
            set_of_lhs.add(lhs)
        for lhs in set_of_lhs:
            offset_tuple = run_info.get_offset_tuple(self.__get_encoded(lhs))
            for i in xrange(len(offset_tuple)):
                union_tuple[i] |= offset_tuple[i]

        if not all(union_tuple):
            self.occured_in_all_run_infos = False

        return union_tuple

    def get_str_variants(self, rhs):
        base = self.__get_encoded(rhs)[0]
        res = [(base,)]
        if not "\0" in base:
            res += [(base + "\0",)]
        if re.match('^[[:print:]]+$', base):
            if not "\n" in base:
                res += [(base + "\n",)]
            if not " " in base:
                res += [(base + " ",)]
            if not '"' in base:
                res += [('"' + base + '"',)]
            if not "'" in base:
                res += [("'" + base + "'",)]
        return res
        # return [ (base+"\n",), (base+"\0",), (base,)]
        # return [ (base+"\n",), (base+"\0",), (base+" ",), ('"'+base+'"',),("'"+base+"'",), (base,)]

    def get_int_variants(self, rhs):
        global HAMMER_LEA
        res = [tuple(self.__get_encoded(rhs))]
        unpack_keys = {1: "B", 2: "H", 4: "L", 8: "Q"}
        bytes = self.cmp.size / 8
        key = unpack_keys.get(bytes, None)
        max = 2 ** (8 * bytes) - 1
        val = struct.unpack(">" + key, rhs)[0]
        max_offset = 1
        if HAMMER_LEA and self.cmp.hammer:
            max_offset = 64
        for i in xrange(1, max_offset + 1):
            res.append(tuple(self.__get_encoded(struct.pack(">" + key, (val + i) % max))))
            res.append(tuple(self.__get_encoded(struct.pack(">" + key, (val - i) % max))))
        return tuple(res)

    def get_sub_variants(self, rhs):
        res = []
        unpack_keys = {1: "B", 2: "H", 4: "L", 8: "Q"}
        bytes = self.cmp.size / 8
        key = unpack_keys.get(bytes, None)
        max = 2 ** (8 * bytes) - 1
        val = struct.unpack(">" + key, rhs)[0]
        for i in xrange(-16, 16):
            res.append(tuple(self.__get_encoded(struct.pack(">" + key, (val + i) % max))))
        return tuple(res)

    def get_variants(self, rhs):
        if self.cmp.type == "STR":
            return self.get_str_variants(rhs)
        elif self.cmp.type == "SUB":
            return self.get_sub_variants(rhs)
        else:
            return self.get_int_variants(rhs)

    def register_dict(self, repl):
        # log_redq("add to dict: %s"%repr(repl))
        if len(repl) > 2:
            havoc_handler.add_to_redqueen_dict(self.cmp.addr, repl)

    def get_mutations(self, orig_run_info):
        if self.mutations != None:
            return self.mutations
        self.mutations = set()
        for (lhs, rhs) in self.cmp.run_info_to_pairs[orig_run_info]:
            if self.enc.is_redundant(self.cmp, lhs, rhs):
                continue
            pattern_tuple = tuple(self.__get_encoded(lhs))
            offsets_tuple = orig_run_info.get_offset_tuple(pattern_tuple)

            offsets_tuple = self.__restrict_offset_tuple(offsets_tuple, orig_run_info)
            if not all(offsets_tuple):
                continue
            self.register_dict(rhs)
            for offset_tuple in itertools.islice(itertools.product(*offsets_tuple), MAX_NUMBER_PERMUTATIONS):
                for repl_tuple in self.get_variants(rhs):
                    if pattern_tuple != repl_tuple:
                        self.mutations.add((offset_tuple, pattern_tuple, repl_tuple))
        return self.mutations

    def is_interessting(self, orig_run_info, num_runs):
        mutations = self.get_mutations(orig_run_info)
        if len(mutations) > 0 and len(mutations) < 256:
            return True
        return self.occured_in_all_run_infos

    def could_be_hash(self):
        always_found = len(self.run_infos_where_not_all_found) == 0
        return always_found and self.cmp._could_be_hash()
