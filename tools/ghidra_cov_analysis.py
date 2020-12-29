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
print_missing = False
# ignore funcitons with less than n blocks?
ignore_threshold = 4
# detailed log of edge scanning
verbose = False

service = None
if state.getTool():
    service = state.getTool().getService(ColorizingService)
    if not service:
        print "Can't find ColorizingService service"

def colorize_test(address):
    anotherAddress = currentAddress.add(10)
    setBackgroundColor(anotherAddress, Color.YELLOW)

    # create an address set with values you want to change
    addresses = AddressSet()
    addresses.add(currentAddress.add(10))
    addresses.add(currentAddress.add(11))
    addresses.add(currentAddress.add(12))
    setBackgroundColor(addresses, Color(100, 100, 200))

def read_edges(tracefile):
    addr = getCurrentProgram().getAddressFactory()
    unique_edges = list()
    with open(tracefile) as trace:
        for line in trace.readlines():
            src,sep,rest = line.rstrip().partition(",")
            dst,sep,rest = line.rstrip().partition(",")
            #print "edge: < 0x%08x, 0x%08x >" % (src,dst)
            addr_src = addr.getAddress("0x%s" % src)
            addr_dst = addr.getAddress("0x%s" % dst)
            unique_edges.append([addr_src, addr_dst])

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


blocklist=list()

def check_block(block, edge=None, indent=" "):
    global blocklist

    # only process new found blocks
    if block in blocklist:
        if verbose:
            print indent + "`-> block %s already known, skipping.." % block.getName()
        return

    # Recursively check any blocks reached unconditionally from this one
    if verbose:
        print indent + "`-> added block %s, checking destinations.." % block.getName()
    indent=indent+"  "

    # Mark this block. We have definitely reached it.
    blocklist.append(block)
    mark_new_block(block)

    # also trace this blocks unconditional/direct destinations, since PT won't trigger events on them
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

def mark_new_block(block):
    #show_block(block)
    if service:
        setBackgroundColor(block, Color.GREEN)

def mark_new_edge(edge):
    if service:
        #setBackgroundColor(edge[0], Color.CYAN)
        #setBackgroundColor(edge[1], Color.CYAN)
        listing = getCurrentProgram().getListing()
        listing.setComment(edge[0], CodeUnit.EOL_COMMENT, "edge target: 0x%08x" % edge[1].getUnsignedOffset())
        listing.setComment(edge[1], CodeUnit.EOL_COMMENT, "edge source: 0x%08x" % edge[0].getUnsignedOffset())

def scan_by_edges(model, edges):

    unmapped_edges = 0

    for edge in edges:
        if verbose:
            print "Searching blocks for edge < 0x%08x, 0x%08x >.." % (edge[0].getUnsignedOffset(), edge[1].getUnsignedOffset())
        found = 0

        # jmp(), call() point at begin of a block, ret() points somewhere right after call()
        b = model.getCodeBlockAt(edge[1], monitor)
        if b:
            #print "-> check jmp/call target block"
            check_block(b, edge)
        else:
            blocks = model.getCodeBlocksContaining(edge[1], monitor)
            #print "-> check ret target block"
            if (len(blocks) > 1):
                printf("Ambigious code block for edge < 0x%08x, 0x%08x >. Supplied the wrong binary?" % (edge[0].getUnsignedOffset(), edge[1].getUnsignedOffset()))
            for b in blocks:
                check_block(b, edge)
                found += 1

        # source pointers will be mostly within a block.
        # this also catches direct hits (getCodeBlockAt(edge[0]))
        blocks = model.getCodeBlocksContaining(edge[0], monitor)
        #print "-> jmp/call/ret from source"
        if(len(blocks) > 1):
            printf("Ambigious code block for edge < 0x%08x, 0x%08x >. Supplied the wrong binary?" % (edge[0].getUnsignedOffset(), edge[1].getUnsignedOffset()))
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

    edges = read_edges("/tmp/edges_uniq.lst")

    model = BasicBlockModel(getCurrentProgram())
    print "Block model: %s" % model.getName()
    print "Ignore threshold: %d" % ignore_threshold
    print "Print missing: %s" % print_missing
    print "Verbose=%s" % verbose

    ##
    # Scan program and mark any blocks we reached
    ##
    unmapped_edges = scan_by_edges(model, edges)

    ##
    # Compute blocks reached/unreached by function
    # While at it, also count the total number of base blocks
    ##
    BlockIter = model.getCodeBlocks(monitor)
    total_blocks = 0
    reached_map = dict() # map of reached blocks by function
    blocks_map = dict()  # map of total blocks by function
    while BlockIter.hasNext():
        total_blocks += 1
        block = BlockIter.next()
        addr = block.getFirstStartAddress()
        func = getFunctionContaining(addr)

        if func in blocks_map:
            blocks_map[func] += 1
        else:
            blocks_map[func] = 1

        if block in blocklist:
            if func in reached_map:
                reached_map[func] += 1
            else:
                reached_map[func] = 1

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
            if func not in reached_map and blocks > ignore_threshold:
                print "Missed: %3d blocks in %s" % (blocks, func)


    ##
    # Overall Summary
    ##
    block_cov = len(blocklist) * 100 / total_blocks
    func_cov = len(reached_map) * 100 / len(blocks_map)
    print
    print "Total blocks in file: %6d" % total_blocks
    print "Total edges in trace: %6d" % len(edges)
    print "Failed to map edges:  %6d" % unmapped_edges
    print
    print "Total reached funcs:  %5d / %5d (%d%%)" % (len(reached_map), len(blocks_map), func_cov)
    print "Total reached blocks: %5d / %5d (%d%%)" % (len(blocklist), total_blocks, block_cov)
    print " ..in reached funcs:  %5d / %5d (%d%%)" % (len(blocklist), total_blocks_reachable, 100*len(blocklist)/total_blocks_reachable)
    print

main()
