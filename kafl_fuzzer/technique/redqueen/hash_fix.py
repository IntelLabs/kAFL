# Copyright (C) 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright (C) 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Redqueen Checksum Fixer
"""

import traceback
from array import array

from common.log import logger
from .parser import RedqueenRunInfo
from .cmp import Cmp

MAX_NUMBER_PERMUTATIONS = 100000


class HashFixer:

    def __init__(self, qemu, rq_state):
        self.qemu = qemu
        self.addrs = rq_state.get_candidate_hash_addrs()
        self.redqueen_state = rq_state
        self.blacklisted_addrs = set()

    def get_broken_cmps(self, data):
        broken_cmps = []
        res, run_info = self.get_cmps(data)
        for addr in res:
            for cmp in res[addr]:
                if not cmp.was_true_in(run_info) and not cmp.addr in self.blacklisted_addrs:
                    broken_cmps.append(cmp)
        return broken_cmps, run_info

    def get_cmps(self, data):
        self.qemu.set_payload(data)
        logger.debug("hashfix run in rq mode")
        self.qemu.send_rq_set_whitelist_instrumentation()
        self.qemu.send_enable_redqueen()
        self.qemu.send_payload(timeout_detection=True, apply_patches=True)
        logger.debug("hashfix run in non rq mode")
        self.qemu.send_disable_redqueen()
        self.qemu.send_payload(timeout_detection=True, apply_patches=True)
        logger.debug("hashfix done running, now parsing")
        res = self.parse_redqueen_results(data)
        logger.debug("hashfix done parsing")
        return res

    def mark_unfixable(self, cmp):
        logger.debug("Unfixable cmp at: %x" % cmp.addr)
        self.blacklisted_addrs.add(cmp.addr)
        self.redqueen_state.blacklist_hash_addr(cmp.addr)

    def get_shape(self, redqueen_results):
        res = {}
        for addr in redqueen_results:
            res[addr] = len(redqueen_results[addr])
        return res

    def try_fix_data(self, data):
        self.qemu.send_payload(timeout_detection=True, apply_patches=False)
        self.qemu.send_payload(timeout_detection=True, apply_patches=True)
        logger.debug("PATCHES %s\n" % repr(list(map(hex, self.redqueen_state.get_candidate_hash_addrs()))))
        logger.debug("BLACKLIST %s\n" % repr(list(map(hex, self.redqueen_state.get_blacklisted_hash_addrs()))))
        self.redqueen_state.update_redqueen_patches(self.qemu.redqueen_workdir)
        self.redqueen_state.update_redqueen_whitelist(self.qemu.redqueen_workdir,
                                                      self.redqueen_state.get_candidate_hash_addrs())
        fixed_data = array('B', data)
        orig_cmps, _ = self.get_cmps(fixed_data)
        shape = self.get_shape(orig_cmps)
        logger.debug("shape of hashes: ")
        for addr in shape:
            logger.debug("\t%x: %d" % (addr, shape[addr]))

        if len(shape) == 0:
            return fixed_data

        num_iters = min(len(orig_cmps) ** 2 + 1, len(orig_cmps) * 3 + 1)
        num_cmps = sum(shape.values()) + 1
        if num_iters < num_cmps:
            num_iters = num_cmps

        logger.debug("try fixing for %d iters" % num_iters)
        for i in range(num_iters):
            broken_checks, run_info = self.get_broken_cmps(fixed_data)
            logger.debug("got %d broken checks\n" % len(broken_checks))
            if not broken_checks:
                return fixed_data
            cmp = broken_checks.pop(-1)
            if not self.try_fix_cmp(shape, fixed_data, run_info, cmp):
                logger.debug("cmp at %x unfixable:" % cmp.addr)
                self.mark_unfixable(cmp)
        broken_checks, run_info = self.get_broken_cmps(fixed_data)
        for cmp in broken_checks:
            self.mark_unfixable(cmp)
        return False

    def parse_redqueen_results(self, data):
        res = {}
        rq_res = parser.read_file(self.qemu.redqueen_workdir.redqueen())
        data_string = "".join(map(chr, data))
        run_info = RedqueenRunInfo(1, False, rq_res, data_string)
        for line in run_info.hook_info.splitlines():
            addr, type, size, is_imm, lhs, rhs = parser.RedqueenInfo.parse_line(line)
            assert (type == "CMP")
            res[addr] = res.get(addr, [])
            cmp = Cmp(addr, type, size, is_imm)
            cmp.index = len(res[addr])
            res[addr].append(cmp)
            cmp.add_result(run_info, lhs, rhs)
        return res, run_info

    @staticmethod
    def replace_data(data, offset, repl):
        for o in range(len(repl)):
            data[offset + o] = repl[o]

    def try_fix_cmp_with(self, shape, fixed_data, cmp, offsets, lhs, rhs, enc):
        logger.debug("Trying mutation %s" % (repr((offsets, lhs, rhs, enc))))
        if list(map(len, lhs)) != list(map(len, rhs)):
            return False
        self.redqueen_state.update_redqueen_whitelist(self.qemu.redqueen_workdir,
                                                      self.redqueen_state.get_candidate_hash_addrs())
        try:
            if self.try_fix_cmp_offset(shape, fixed_data, cmp, offsets, rhs):
                logger.debug("Mutation fixed it")
                return True
            logger.debug("Mutation didn't Fix it")
            return False
        except Exception as e:
            logger.error("fixing hash failed %s" % traceback.format_exc())
            raise e

    def try_fix_cmp(self, shape, fixed_data, run_info, cmp):
        known_offsets = self.redqueen_state.get_candidate_file_offsets(cmp.addr)
        logger.debug("known offsets for: %x = %s" % (cmp.addr, known_offsets))
        mutations = [x for x in cmp.calc_mutations(run_info, 1)]
        for (offsets, lhs, rhs, enc) in cmp.calc_mutations(run_info, 1):
            if offsets in known_offsets:
                if self.try_fix_cmp_with(shape, fixed_data, cmp, offsets, lhs, rhs, enc):
                    return True
        for (offsets, lhs, rhs, enc) in cmp.calc_mutations(run_info, 1):
            if not offsets in known_offsets:
                if self.try_fix_cmp_with(shape, fixed_data, cmp, offsets, lhs, rhs, enc):
                    return True
        return False

    def does_data_fix_cmp(self, shape, data, cmp):
        res, run_info = self.get_cmps(data)
        return shape == self.get_shape(res) and res[cmp.addr][cmp.index].was_true_in(run_info)

    def try_fix_cmp_offset(self, shape, data, cmp, offsets, repls):
        backup = {}
        for i, repl in zip(offsets, repls):
            backup[i] = data[i:i + len(repl)]
            HashFixer.replace_data(data, i, array('B', repl))
        if self.does_data_fix_cmp(shape, data, cmp):
            logger.debug("found candidate offset %x %s" % (cmp.addr, repr(offsets)))
            self.redqueen_state.add_candidate_file_offset(cmp.addr, tuple(offsets))
            return True
        for i in offsets:
            HashFixer.replace_data(data, i, backup[i])
        return False
