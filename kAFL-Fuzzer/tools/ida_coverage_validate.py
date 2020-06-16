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

import json
from idaapi import *
from idautils import *
from idc import *

PRINT_DETAILS = True;
PRINT_COMMENTS = True;


class CovInfo:
    def __init__(self):
        self.stack = []
        self.covered_offsets = set()

    def is_partial_covered(self, funcea):
        instrs_found = 0
        instrs_has = 0
        for head in self.each_instrea_for_func(funcea):
            instrs_has += 1
            if head in self.covered_offsets:
                instrs_found += 1
        return instrs_has != instrs_found and instrs_found != 0

    def each_bb_for_func(self, funcea):
        func = get_func(funcea)
        bbs = FlowChart(func)
        for bb in bbs:
            yield bb

    def each_instrea_for_bb(self, bb):
        for head in Heads(bb.startEA, bb.endEA):
            yield head

    def each_instrea_for_func(self, funcea):
        for (startea, endea) in Chunks(funcea):
            for head in Heads(startea, endea):
                yield head

    def each_funcea(self):
        for segea in Segments():
            for funcea in Functions(segea, SegEnd(segea)):
                yield funcea

    def get_partial_functions(self):
        res = []
        for funcea in self.each_funcea():
            if self.is_partial_covered(funcea):
                res.append(GetFunctionName(funcea))
        return res

    def color_instruction(self, ea, color):
        idc.SetColor(ea, idc.CIC_ITEM, color)

    def color_bb(self, funcea, bbid, color):
        p = idaapi.node_info_t()
        p.bg_color = color
        idaapi.set_node_info2(funcea, bbid, p, idaapi.NIF_BG_COLOR | idaapi.NIF_FRAME_COLOR)

    def transition(self, fromaddr, toaddr):
        if PRINT_DETAILS:
            print("   -> %x -> %x" % (fromaddr, toaddr))
        if should_have_trace_comment(fromaddr):
            new_string = "%x" % toaddr
            if NameEx(fromaddr, toaddr) != "":
                new_string = NameEx(fromaddr, toaddr)
            add_comment(fromaddr, new_string)

    def run(self, addr, slice):
        if PRINT_DETAILS:
            print("Run on %x %s" % (addr, map(lambda e: map(lambda v: "%x" % v, e), slice)))
        curr = None
        while True:
            if not curr and slice:
                curr = slice.pop(0)
            addr, reason = self.run_until_unclear(addr)
            if not reason:
                if slice:
                    print("Exited trace at %x but some trace remains %s " % (addr, slice))
                return
            else:
                if not curr:
                    return
                elif addr != curr[0]:
                    print("Address missmatch: reached %x, but next edge is %x -> %x" % (addr, curr[0], curr[1]))
                    return
                else:
                    self.transition(curr[0], curr[1])
                    addr = curr[1]
                    curr = None

    def run_until_unclear(self, curEa):
        while (True):
            if not isinstance(curEa, (int, long)):
                curEa = idc.LocByName(curEa)
            mnem = idc.GetMnem(curEa)
            if (mnem == ''):
                # print ("Invalid address %08x" %(curEa))
                return curEa, None

            # print("    -> %x %s"%(curEa, mnem))
            self.color_instruction(curEa, 0x76d0b7)
            self.covered_offsets.add(curEa)

            if (mnem == "call" or mnem == "jmp"):
                targetEa = idc.GetOperandValue(curEa, 0)  # Only if the Operand is idc.o_near
                if PRINT_DETAILS:
                    print
                    "got jmp/call %x -> %x" % (curEa, targetEa)
                nextEa = idc.NextHead(curEa)
                if (mnem == "call"):
                    self.stack.append(nextEa)
                opType = idc.GetOpType(curEa, 0)
                if opType == idc.o_mem or opType == idc.o_reg or opType == idc.o_displ or opType == idc.o_phrase:
                    return curEa, "call_ind"
                else:
                    curEa = idc.GetOperandValue(curEa, 0)

            elif (mnem == "ja" or mnem == "jae" or mnem == "jb" or mnem == "jbe" or
                  mnem == "je" or mnem == "jg" or mnem == "jge" or mnem == "jl" or mnem == "jle" or
                  mnem == "jna" or mnem == "jnae" or mnem == "jnb" or mnem == "jnbe" or mnem == "jnc" or
                  mnem == "jne" or mnem == "jng" or mnem == "jnge" or mnem == "jnl" or mnem == "jnle" or
                  mnem == "jno" or mnem == "jns" or mnem == "jnz" or mnem == "jo" or mnem == "jp" or
                  mnem == "jpe" or mnem == "jpo" or mnem == "js" or mnem == "jz" or mnem == "jp" or
                  mnem == "jc" or mnem == "jecxz" or mnem == "jcxz" or mnem == "jrcxz" or
                  mnem == "loop" or mnem == "loope" or mnem == "loopne" or mnem == "loopnz" or mnem == "loopz"):
                return curEa, "jmp_cond"

            elif (mnem == "ret" or mnem == "retn"):
                return curEa, "ret"
            else:
                curEa = idc.NextHead(curEa)

    def clear_colors(self):
        for funcea in self.each_funcea():
            for head in self.each_instrea_for_func(funcea):
                self.color_instruction(head, 0x7679d0)
            for bb in self.each_bb_for_func(funcea):
                self.color_bb(funcea, bb.id, 0x7679d0)

    def get_color_for_bb(self, funcea, bb):
        covered = 0
        instrs = 0
        for head in self.each_instrea_for_bb(bb):
            if head in self.covered_offsets:
                covered += 1
            instrs += 1
        if covered == 0:
            return 0x7679d0
        if covered != instrs:
            return 0x0887FA
        return 0x76d0b7

    def finalize_colors(self):
        for funcea in self.each_funcea():
            for bb in self.each_bb_for_func(funcea):
                self.color_bb(funcea, bb.id, self.get_color_for_bb(funcea, bb))


def get_mem(mem_addr, value, accesslen):
    return str(repr(value.decode("hex")[4:4 + accesslen]))


def add_comment(addr, str):
    comm = GetCommentEx(addr, 0)
    if not comm:
        MakeComm(addr, "{{%s}}" % str)
    elif not str in comm:
        m = re.search(r'(.*){{(.*)}}(.*)', comm)
        if not m:
            MakeComm(addr, "%s {{%s}}" % (comm, str))
        else:
            if (not str in m.group(2)) and (not len(m.group(2)) > 100):
                new_str = m.group(2) + " " + str
                if len(new_str) > 100:
                    new_str = new_str + " ..."
                # print(new_str, len(new_str))
                MakeComm(addr, "%s{{%s}}%s" % (m.group(1), new_str, m.group(3)))


def should_have_mem_comment(addr):
    mnem = idc.GetMnem(addr)
    if "ret" in mnem or mnem == "cmp":
        return False
    return True


def should_have_trace_comment(addr):
    type = idc.GetOpType(addr, 0)
    mnem = idc.GetMnem(addr)
    if type in [idaapi.o_near, idaapi.o_far, idaapi.o_imm]:
        return False
    return True


def get_disasm_plain(addr):
    return GetDisasm(addr).split(";")[0]


def mem_size(addr):
    instr = get_disasm_plain(addr)
    if "byte" in instr:
        return 1
    if "word" in instr:
        return 2
    if "dword" in instr:
        return 4
    if "qword" in instr:
        return 8
    return 8


def add_mem_comment(line):
    instr_addr = line["access"]
    if should_have_mem_comment(instr_addr):
        mem_addr, value = line["mem"]
        add_comment(instr_addr, get_mem(mem_addr, value, mem_size(instr_addr)))


def parse_rq_line(line):
    m = re.search(r'([a-fA-F0-9]+)\s+(STR|CMP|SUB) (8|16|32|64|512)\s+([a-fA-F0-9]+)\s*-\s*([a-fA-F0-9]+)\s*(IMM)?',
                  line)
    type = m.group(2)
    size = m.group(3)
    addr = int(m.group(1), base=16)
    is_imm = not not m.group(6)
    lhs = repr(m.group(4).decode('hex'))
    rhs = repr(m.group(5).decode('hex'))
    return addr, size, lhs, rhs, is_imm


def add_cmp_comment(line):
    addr, size, lhs, rhs, is_imm = parse_rq_line(line["redq"])
    if size == "STR":
        return
    if is_imm:
        add_comment(addr, str(lhs))
    else:
        desc = str("%s:%s" % (lhs, rhs))
        add_comment(addr, desc)


def read_file(path):
    with open(path, 'r') as f:
        return [json.loads(line) for line in f.readlines()]


def parse_file(path):
    trace = read_file(path)
    res = []
    curr_input_filename = None
    for line in trace:
        if "edge" in line:
            if not res:
                print("warning, got edge before trace enable, corruped trace?")
            else:
                res[-1][1].append(line["edge"])
        if "trace_enable" in line:
            res.append([line["trace_enable"], []])
        if "access" in line:
            if PRINT_COMMENTS:
                add_mem_comment(line)
        if "redq" in line:
            if PRINT_COMMENTS:
                add_cmp_comment(line)
        if "input_path" in line:
            curr_input_filename = line[
                "input_path"]  # TODO use MakeExtraLineA to display which input triggered which basic blocks
    return res


def dedup_slices(results):
    return results
    res = set()
    for (start, slice) in results:
        res.add((start, tuple(map(tuple, slice))))
    return res


print("=====================================")
file = idc.AskFile(0, "*.rqse", "Select a redqueen_se file")
results = parse_file(file)
results = dedup_slices(results)

cov = CovInfo()
cov.clear_colors()

for (start, slice) in results:
    cov.run(start, list(slice))

cov.finalize_colors()
# print cov.run_until_unclear(0x41EF16)
print
cov.get_partial_functions()
