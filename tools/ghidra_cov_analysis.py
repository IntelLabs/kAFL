#
# Visualize Coverage of Basic Block Edges in Ghidra
#
# Copyright 2020 Intel Corporation
# SPDX-License-Identifier: MIT
#

# Ghidra script to find + colorize blocks based on a list of edge transitions.
# Edge transitions are read from external file. Format is one edge on each line:
#
# 579094,579152
# 579102,579108
# 579102,579960
# 579108,579114
# 579108,579632
# 579158,579164
# [...]
#
# Note that processing complete traces will be quite slow. Instead, the input
# should be an aggregate list of all your traces with any duplicates removed.
#
#@category Fuzzing

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

from java.awt import Color

service = None
if state.getTool():
    service = state.getTool().getService(ColorizingService)
    if not service:
        print "Can't find ColorizingService service"

blocklist = []
unreached = dict()
reached = dict()

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
            src,dst = line.rstrip().split(",")
            #print "edge: < 0x%08x, 0x%08x >" % (src,dst)
            addr_src = addr.getAddress("0x%x" % int(src))
            addr_dst = addr.getAddress("0x%x" % int(dst))
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

    print "Listing all entry sources to this block:"
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
        destAddr = destRef.getReferent().getUnsignedOffset()
        print "  - 0x%08x (%08d)" % (destAddr, destAddr)

    print "Addresses in this block:"
    AddrIter = block.getAddresses(True)
    while AddrIter.hasNext():
        Addr = AddrIter.next()
        print "  - 0x%08x" % Addr.getUnsignedOffset()


def check_block(block, edge=None):

    # only process new found blocks
    if block in blocklist:
        return;

    # Mark this block. We have definitely reached it.
    blocklist.append(block)
    mark_new_block(block)

    # Recursively check any blocks reached unconditionally from this one
    destIter = block.getDestinations(monitor);
    #print "Dest refs from this block:"
    while (destIter.hasNext()):
        destRef = destIter.next()
        #destAddr = destRef.getReferent().getUnsignedOffset()
        #print "  - 0x%08x (%08d)" % (destAddr, destAddr)
        if destRef.getFlowType().isUnConditional():
            check_block(destRef.getDestinationBlock())

    # If we know the edge that led us here, try and find the corresponding source block
    if not edge:
        return

    found=0
    srcIter = block.getSources(monitor);
    while (srcIter.hasNext()):
        srcRef = srcIter.next()
        srcAddr = srcRef.getReferent().getUnsignedOffset()
        if srcAddr == edge[0]:
            check_block(srcRef.getSourceBlock())
            found += 1

    # In case we TBD: are we missing out on some source blocks here?
    if found == 0:
        print "WARN: Could not find source block for edge < 0x%08x, 0x%08x >" % (
                edge[0].getUnsignedOffset(),
                edge[1].getUnsignedOffset())
        #show_block(block)


def mark_new_block(block):

    # Mark this block and record the 
    if service:
        setBackgroundColor(block, Color.GREEN)


# really, we want a way to find the block based on edge destination...this is way too slow..
def scan_by_edges(blocks, edges):

    unmapped_edges = 0

    for edge in edges:
        #print "Searching blocks for edge <0x%08x,0x%08x>.." % (edge[0], edge[1])
        for addr in [edge[0], edge[1]]:
            found = 0
            block = blocks.getCodeBlockAt(addr, monitor)
            if block:
                check_block(block)
                found += 1
            else:
                for block in blocks.getCodeBlocksContaining(addr, monitor):
                    check_block(block)
                    found += 1
                    if found > 1:
                        print "WARN: Found multiple blocks for this edge?!"
                        #show_block(block)

            if found == 0:
                unmapped_edges += 1
                print "Could not map edge < 0x%08x, 0x%08x >" % (
                                                    edge[0].getUnsignedOffset(),
                                                    edge[1].getUnsignedOffset())

    return unmapped_edges

def main():

    edges = read_edges("/tmp/edges_uniq.lst")

    blocks = BasicBlockModel(getCurrentProgram())
    print "Block Model: %s" % blocks.getName()

    ##
    # Scan program and mark any blocks we reached
    ##
    unmapped_edges = scan_by_edges(blocks, edges)

    ##
    # Compute blocks reached/unreached by function
    # While at it, also count the total number of base blocks
    ##
    BlockIter = blocks.getCodeBlocks(monitor)
    total_blocks = 0
    while BlockIter.hasNext():
        total_blocks += 1
        block = BlockIter.next()
        addr = block.getFirstStartAddress()
        func = getFunctionContaining(addr)
        if block in blocklist:
            if func in reached:
                reached[func] += 1
            else:
                reached[func] = 1
        else:
            if func in unreached:
                unreached[func] += 1
            else:
                unreached[func] = 1

    ##
    ## Summarize blocks reached/not reached by function
    ##
    print
    min_report_blocks=10
    for k,v in sorted(reached.items(), key=lambda x: x[1]):
        total = v+unreached.get(k,0)
        percent = v*100/total
        if v > min_report_blocks and total > min_report_blocks:
            print "Reached: %3d blocks (%3d%%) in %s" % (v, percent, k)

    print
    for k,v in sorted(unreached.items(), key=lambda x: x[1]):
        total = v+reached.get(k,0)
        percent = v*100/total
        if v > min_report_blocks and total > min_report_blocks:
            print "Missed: %3d blocks (%3d%%) in %s" % (v, percent, k)


    ##
    # Overall Summary
    ##
    bb_cov = len(blocklist)*100/total_blocks
    print
    print "Total blocks in file: %6d" % total_blocks
    print "Total edges in trace: %6d" % len(edges)
    print "Failed to map edges:  %6d" % unmapped_edges
    print
    print "Total reached funcs:  %6d" % len(reached)
    print "Partly missed funcs:  %6d" % len(unreached)
    print "Total reached blocks: %6d (%d%%)" % (len(blocklist), bb_cov)

main()
