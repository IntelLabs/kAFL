# Visualize Coverage of Basic Block Edges in Ghidra
#
# Copyright 2020 Intel Corporation
# SPDX-License-Identifier: MIT
#
# Ghidra script to find + colorize blocks based on a list of edge transitions.
# Edge transitions are read from external file '/tmp/edges_uniq.lst'.
#
# Format is one edge on each line:
#
# 579094,579152
# 579102,579108
# 579102,579960
# 579108,579114
# 579108,579632
# 579158,579164
# [...]
#
# Processing large amounts of traces can be quite slow.
# Consider aggregating traces using sort -u.
#
#@category Fuzzing
#@author Steffen Schulz

from ghidra.app.plugin.core.colorizer import ColorizingService
from ghidra.app.script import GhidraScript
from ghidra.program.model.address import Address
from ghidra.program.model.address import AddressSet
from ghidra.program.model.address import GenericAddress

from ghidra.program.model.block import BasicBlockModel
from ghidra.program.model.block import SimpleBlockModel
from ghidra.program.model.block import CodeBlockModel

from ghidra.program.model.listing import ListingStub
from ghidra.program.flatapi import FlatProgramAPI

from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.listing import Listing

from java.awt import Color

# print list of missing/uncovered functions?
print_missing = True
# report blocks that are only reached implicitly (unconditional jmp/call)
print_implicit = True
# ignore funcitons with less than n blocks?
ignore_threshold = 4
# detailed log of edge scanning
verbose = False

# functions to exclude from cov total
func_blacklist = []

service = None
if state.getTool():
    service = state.getTool().getService(ColorizingService)
    if not service:
        print "Can't find ColorizingService service"

def num2color(v):
    if v >= 200:
        return Color.PINK
    if v >= 64:
        return Color.ORANGE
    if v >= 1:
        return Color.GREEN
    if v == 0:
        return Color.CYAN

def read_edges(tracefile):
    addr = getCurrentProgram().getAddressFactory()
    unique_edges = list()
    with open(tracefile) as trace:
        for line in trace.readlines():
            src,dst,num = line.rstrip().split(',')
            #print "edge: < 0x%s, 0x%s, %s >" % (src,dst,num)
            addr_src = addr.getAddress("0x%s" % src)
            addr_dst = addr.getAddress("0x%s" % dst)
            unique_edges.append([addr_src, addr_dst, int(num,16)])

    return unique_edges

def get_CodeAddressObj(blocks):
    BlockIter = blocks.getCodeBlocks(monitor)
    while BlockIter.hasNext():
        block = BlockIter.next()
        for addr in block.getStartAddresses():
            return addr


def show_block(block):

    print "Info on block %s" % block.getName()

    print "Entry vectors to this block:"
    for entry in block.getStartAddresses():
        print "  - 0x%08x (%08d)" % (entry.getUnsignedOffset(), entry.getUnsignedOffset())

    print "Source refs to this block:"
    srcIter = block.getSources(monitor);
    while (srcIter.hasNext()):
        srcRef = srcIter.next()
        srcAddr = srcRef.getReferent().getUnsignedOffset()
        print "  - 0x%08x (%08d)" % (srcAddr, srcAddr)

    print "Dest refs from this block:"
    destIter = block.getDestinations(monitor);
    while (destIter.hasNext()):
        destRef = destIter.next()
        destAddr = destRef.getReference().getUnsignedOffset()
        print "  - 0x%08x (%08d)" % (destAddr, destAddr)

    print "All addresses in this block:"
    AddrIter = block.getAddresses(True)
    while AddrIter.hasNext():
        Addr = AddrIter.next()
        print "  - 0x%08x" % Addr.getUnsignedOffset()


blocklist = list()
implicit_blocks = list()

def check_block(block, edge=None, indent=" "):
    global blocklist

    # Mark this block. Implicitly reached blocks have edge=None
    mark_new_block(block, edge)

    # Recursively check any blocks reached unconditionally from this one
    if block in blocklist:
        if verbose:
            print indent + "`-> block %s already known, skipping.." % block.getName()
        return

    if verbose:
        print indent + "`-> block %s is new, checking destinations.." % block.getName()
    indent=indent+"  "
    blocklist.append(block)

    # Edges reached by unconditional call/jmp may not be explicitly listed in trace
    # But they may also be false positives. We recursively check them with edge=None
    destIter = block.getDestinations(monitor);
    while (destIter.hasNext()):
        destRef = destIter.next()
        destFlow = destRef.getFlowType()

        # Drop conditional and indirect items. isConditional() does not seem to
        # work, so below we make double-sure to only tag
        # - unconditional/direct calls/jmp
        # - fallthroughs that are not identical with a (conditional) jmp
        if destFlow.isConditional() or destFlow.isIndirect():
            continue

        if str(destFlow) in ["UNCONDITIONAL_CALL", "UNCONDITIONAL_JUMP"]:
            if verbose:
                print indent + "`-> add implicit %s: 0x%08x -> 0x%08x" % (
                        str(destFlow), destRef.getReferent().getUnsignedOffset(), destRef.getReference().getUnsignedOffset())
            check_block(destRef.getDestinationBlock(), indent=indent)
        if verbose:
            print indent + "`-> ignore implicit %s: 0x%08x -> 0x%08x" % (
                    str(destFlow), destRef.getReferent().getUnsignedOffset(), destRef.getReference().getUnsignedOffset())

def mark_new_block(block, edge):
    global implicit_blocks
    global blocklist
    #show_block(block)

    # colorize reached blocks, potentially overriding an earlier (implicitly reached) block
    if edge:
        if service:
            setBackgroundColor(block, num2color(edge[2])) # warm, execution=1+
        if block in implicit_blocks:
            implicit_blocks.remove(block)
    else:
        if block not in blocklist:
            implicit_blocks.append(block)
            if service:
                setBackgroundColor(block, num2color(0)) # cold, executions=0

def clear_markup():
    # only works in GUI mode
    if not service:
        return

    listing = getCurrentProgram().getListing()
    AddrSet = getCurrentProgram().getAddressFactory().getAddressSet()

    clearBackgroundColor(AddrSet)

    CodeIter = listing.getCommentCodeUnitIterator(CodeUnit.EOL_COMMENT, AddrSet)
    while CodeIter.hasNext():
        addr = CodeIter.next()
        addr.setComment(CodeUnit.EOL_COMMENT, "")

def mark_new_edge(edge):
    # only works in GUI mode
    if not service:
        return

    #setBackgroundColor(edge[0], Color.CYAN)
    #setBackgroundColor(edge[1], Color.CYAN)
    listing = getCurrentProgram().getListing()
    srcComment = listing.getComment(CodeUnit.EOL_COMMENT, edge[0])
    srcComment = (srcComment + "\n" if srcComment else "") + "edge dst=0x%08x" % edge[1].getUnsignedOffset()
    listing.setComment(edge[0], CodeUnit.EOL_COMMENT, srcComment)

    dstComment = listing.getComment(CodeUnit.EOL_COMMENT, edge[1])
    dstComment = (dstComment + "\n" if dstComment else "") + "edge src=0x%08x" % edge[0].getUnsignedOffset()
    listing.setComment(edge[1], CodeUnit.EOL_COMMENT, dstComment)

def scan_by_edges(model, edges):

    unmapped_edges = 0

    for edge in edges:
        if verbose:
            print "Searching blocks for edge < 0x%08x, 0x%08x >.." % (edge[0].getUnsignedOffset(), edge[1].getUnsignedOffset())
        found = 0

        # jmp(), call() point at begin of a block, ret() points somewhere right after call()
        b = model.getCodeBlockAt(edge[1], monitor)
        if b:
            if verbose:
                print "Found dest block for edge < 0x%08x, 0x%08x >" % (edge[0].getUnsignedOffset(), edge[1].getUnsignedOffset())
            check_block(b, edge)
            found += 1
        else:
            blocks = model.getCodeBlocksContaining(edge[1], monitor)
            if verbose:
                if (len(blocks) == 1):
                    print "Found dest block for edge < 0x%08x, 0x%08x >" % (edge[0].getUnsignedOffset(), edge[1].getUnsignedOffset())
                if (len(blocks) > 1):
                    print "Ambigious dest block for edge < 0x%08x, 0x%08x >" % (edge[0].getUnsignedOffset(), edge[1].getUnsignedOffset())

            for b in blocks:
                check_block(b, edge)
                found += 1

        # source pointers will be mostly within a block.
        # this also catches direct hits (getCodeBlockAt(edge[0]))
        blocks = model.getCodeBlocksContaining(edge[0], monitor)
        if verbose:
            if(len(blocks) == 1):
                print "Found src block for edge < 0x%08x, 0x%08x >" % (edge[0].getUnsignedOffset(), edge[1].getUnsignedOffset())
            if(len(blocks) > 1):
                print "Ambigious src block for edge < 0x%08x, 0x%08x >" % (edge[0].getUnsignedOffset(), edge[1].getUnsignedOffset())
        for b in blocks:
            check_block(b, edge)
            found += 1

        if found > 0:
            mark_new_edge(edge)
        else:
            unmapped_edges += 1
            print "Warning: Could not map edge < 0x%08x, 0x%08x >. Supplied wrong binary?" % (
                                                    edge[0].getUnsignedOffset(),
                                                    edge[1].getUnsignedOffset())

    return unmapped_edges

def main():

    model = BasicBlockModel(getCurrentProgram())
    print "Block model: %s" % model.getName()
    print "Ignore threshold: %d" % ignore_threshold
    print "Print missing: %s" % print_missing
    print "Verbose=%s" % verbose

    ##
    # Read edges from file, then scan program and mark any reached blocks
    #
    # Input format:
    # One edge per line: "src,dst,num", where num is the number of times the edge was hit
    ##
    clear_markup()
    edges = read_edges("/tmp/edges_uniq.lst")
    unmapped_edges = scan_by_edges(model, edges)

    ##
    # Compute blocks reached/unreached by function
    # While at it, also count the total number of base blocks
    ##
    BlockIter = model.getCodeBlocks(monitor)
    total_blocks = 0
    missing_blocks = 0
    reached_blocks = 0
    reached_map = dict() # map of reached blocks by function
    blocks_map = dict()  # map of total blocks by function
    while BlockIter.hasNext():
        total_blocks += 1
        block = BlockIter.next()
        addr = block.getFirstStartAddress()
        func = str(getFunctionContaining(addr))

        if func in blocks_map:
            blocks_map[func] += 1
        else:
            blocks_map[func] = 1

        if func in func_blacklist:
            if block in blocklist:
                print "Block: addr=%s, name=%s func=%s, reached=%d" % (
                      addr, id(block), func, (block in blocklist))
            continue

        if block in blocklist:
            reached_blocks += 1
            if func in reached_map:
                reached_map[func] += 1
            else:
                reached_map[func] = 1
        else:
            missing_blocks +=1
        #print "Block: addr=%s, name=%s func=%s, reached=%d" % (
        #        addr, id(block), func, (block in blocklist))

    ##
    ## Summarize blocks reached/missed by function
    ##
    print
    total_blocks_reachable=0
    for func, blocks in sorted(reached_map.items(), key=lambda x: str(x[0]).lower):
        total = blocks_map[func]
        percent = blocks * 100 / total
        total_blocks_reachable += total
        if total > ignore_threshold:
            print "Reached: %3d from %3d blocks (%3d%%) in %s" % (blocks, total, percent, func)

    print
    if print_missing:
        for func, blocks in sorted(blocks_map.items(), key=lambda x: str(x[0]).lower):
            if func in func_blacklist:
                print "Ignore: %3d blocks in %s" % (blocks, func)
                continue
            if func not in reached_map and blocks > ignore_threshold:
                print "Missed: %3d blocks in %s" % (blocks, func)

    if print_implicit and len(implicit_blocks):
        print "\nMarked %d implicitly reached blocks:\n\t%s" % (
                len(implicit_blocks), ', '.join(str(x.name) for x in implicit_blocks))

    ##
    # Overall Summary
    ##
    blocks_ignored = 0
    for func in func_blacklist:
        if blocks_map.get(func):
            blocks_ignored += blocks_map[func]
    blocks_ignored = sum([blocks_map.get(func, 0) for func in func_blacklist])

    filtered_blocks = reached_blocks + missing_blocks
    block_cov = reached_blocks * 100 / filtered_blocks
    func_cov = len(reached_map) * 100 / len(blocks_map)

    print
    print "Total blocks in file: %6d" % total_blocks
    print "         blacklisted: %6d" % blocks_ignored
    print "           remaining: %6d" % filtered_blocks
    print
    print "Total edges in trace: %6d" % len(edges)
    print "Failed to map edges:  %6d" % unmapped_edges
    print
    print "Total reached funcs:  %6d / %6d (%d%%)" % (len(reached_map), len(blocks_map), func_cov)
    print "Total reached blocks: %6d / %6d (%d%%)" % (reached_blocks, filtered_blocks, block_cov)
    print " ..in reached funcs:  %6d / %6d (%d%%)" % (reached_blocks, total_blocks_reachable,
                                                      100*reached_blocks/total_blocks_reachable)
    print "  Blocks not reached: %6d" % missing_blocks
    print

main()
