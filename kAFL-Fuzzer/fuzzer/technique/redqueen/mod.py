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

import os.path
from array import array
from shutil import copyfile, rmtree

import parser
from common.debug import log_redq

MAX_NUMBER_PERMUTATIONS = 1000  # number of trials per address, lhs and encoding


class RedqueenInfoGatherer:
    def __init__(self):
        self.num_alternative_inputs = 0
        self.collected_infos_path = None
        self.workdir = None
        self.num_mutations = 0
        self.verbose = False

    def make_paths(self, workdir):
        self.workdir = workdir
        self.collected_infos_path = workdir.base_path + "/collected_infos"
        rmtree(self.collected_infos_path, ignore_errors=True)
        os.mkdir(self.collected_infos_path)

    def get_info(self, input_data):
        self.num_alternative_inputs += 1
        self.save_rq_data(self.num_alternative_inputs, input_data)
        print("redqueen saving stuff....")
        with open(self.collected_infos_path + "/input_%d.bin" % (self.num_alternative_inputs), "wb") as f:
            f.write(input_data)

    def save_rq_data(self, id, data):
        if os.path.exists(self.workdir.redqueen()):
            copyfile(self.workdir.redqueen(), "%s/redqueen_result_%d.txt" % (self.collected_infos_path, id))
            # copyfile(self.workdir.code_dump(),"%s/redqueen_vm.img"%(self.collected_infos_path))

    def __get_redqueen_proposals(self):
        num_colored_versions = self.num_alternative_inputs
        orig_id = self.num_alternative_inputs
        rq_info, (num_mutations, offset_to_lhs_to_rhs_to_info) = parser.parse_rq(self.collected_infos_path,
                                                                                 num_colored_versions, orig_id)
        self.rq_info = rq_info
        self.rq_offsets_to_lhs_to_rhs_to_info = offset_to_lhs_to_rhs_to_info
        self.num_mutations += num_mutations

    def get_hash_candidates(self):
        return self.rq_info.get_hash_candidates()

    def get_boring_cmps(self):
        return self.rq_info.boring_cmps

    def get_proposals(self):
        self.__get_redqueen_proposals()

    def enumerate_mutations(self):
        for offsets in self.rq_offsets_to_lhs_to_rhs_to_info:
            for lhs in self.rq_offsets_to_lhs_to_rhs_to_info[offsets]:
                for rhs in self.rq_offsets_to_lhs_to_rhs_to_info[offsets][lhs]:
                    yield (offsets, lhs, rhs, self.rq_offsets_to_lhs_to_rhs_to_info[offsets][lhs][rhs])

    def run_mutate_redqueen(self, payload_array, func, default_info):
        for (offset, lhs, rhs, info) in self.enumerate_mutations():
            if self.verbose:
                log_redq("redqueen fuzz data %s" % repr((offset, lhs, rhs, info)))

            def run(data):
                default_info["redqueen"] = [repr(lhs), repr(rhs)] + list(info.infos)
                func(data, default_info)

            RedqueenInfoGatherer.fuzz_data(payload_array, run, offset, lhs, rhs)

    def get_num_mutations(self):
        return self.num_mutations

    @staticmethod
    def replace_data(data, offset, repl):
        for o in range(len(repl)):
            data[offset + o] = repl[o]

    @staticmethod
    def fuzz_data_same_len(data, func, offset_tuple, repl_tuple):
        backup = {}
        for i, repl in zip(offset_tuple, repl_tuple):
            for j in xrange(i, i + len(repl)):
                backup[j] = data[j]

        for i, repl in zip(offset_tuple, repl_tuple):
            RedqueenInfoGatherer.replace_data(data, i, array('B', repl))
        func(data.tostring())
        for i in backup:
            data[i] = backup[i]

    @staticmethod
    def fuzz_data_different_len(data, func, offset_tuple, pat_length_tuple, repl_tuple):
        res_str = ""
        last_offset = 0
        for i, orig_length, repl in zip(sorted(offset_tuple), pat_length_tuple, repl_tuple):
            res_str += data[last_offset:i].tostring()
            res_str += repl
            last_offset = i + orig_length
        res_str += data[last_offset:].tostring()
        func(res_str)

    @staticmethod
    def fuzz_data(data, func, offset_tuple, pat_tuple, repl_tuple):
        pat_len_tuple = map(len, pat_tuple)
        if pat_len_tuple != map(len, repl_tuple):
            RedqueenInfoGatherer.fuzz_data_different_len(data, func, offset_tuple, pat_len_tuple, repl_tuple)
        else:
            RedqueenInfoGatherer.fuzz_data_same_len(data, func, offset_tuple, repl_tuple)
