#!/usr/bin/env python3
#
# Copyright (C) 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright (C) 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Given a AFL or kAFL workdir, process the contained corpus in
kAFL Qemu/KVM to obtain PT traces of individual inputs.  

The individual traces are saved to $workdir/traces/.
"""

import os
import sys

import time
import glob
import shutil
import msgpack
import lz4.frame as lz4
import re

from common.config import DebugConfiguration
from common.self_check import self_check, post_self_check
import common.color
from operator import itemgetter

from common.debug import log_debug, enable_logging
from common.util import prepare_working_dir, read_binary_file, print_note, print_fail, print_warning
from common.qemu import qemu

import json
import csv


class TraceParser:
    def __init__(self):
        self.known_bbs = set()
        self.known_edges = set()

    def parse_trace_file(self, trace_file, trace_id):
        if not os.path.isfile(trace_file):
            print_note("Could not find trace file %s, skipping.." % trace_file)
            return None

        gaps = set()
        bbs = set()
        edges = set()
        with lz4.LZ4FrameFile(trace_file, 'rb') as f:
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
                    bbs.add(m.group(2))
                    bbs.add(m.group(3))
        return {'bbs': bbs, 'edges': edges, 'gaps': gaps}

    def get_cov_by_trace(self, trace_file, trace_id):
        # note the return new BB count depends on the order in which traces are parsed
        findings = self.parse_trace_file(trace_file, trace_id)
        if not findings: 
            return 0, 0
        if len(findings['gaps']) > 1:
            print_note("Got multiple gaps in trace %s" % trace_file)

        num_new_bbs = len(findings['bbs'] - self.known_bbs)
        num_new_edges = len(findings['edges'] - self.known_edges)
        self.known_bbs.update(findings['bbs'])
        self.known_edges.update(findings['edges'])
        return num_new_bbs, num_new_edges


def afl_workdir_iterator(work_dir):
    id_to_time = dict()
    input_id_time = list()
    nid = 0
    start_time = time.time()
    with open(work_dir + "/plot_data", 'r') as f:
        afl_plot = csv.reader(f, delimiter=',')
        next(afl_plot) # skip first line
        for row in afl_plot:
            paths = int(row[3].strip())
            while paths > nid:
                #print("%d->%d" % (nid, paths))
                timestamp = int(row[0])
                if timestamp < start_time:
                    start_time = timestamp
                id_to_time.update({nid:timestamp})
                nid += 1

    # match any identified payloads - poor man's variant of /{crashes,hangs,queue}/id*
    for input_file in glob.glob(work_dir + "/[chq][rau][ane][sgu][hse]*/id:0*"):
        if not input_file:
            return
        input_name = os.path.basename(input_file)
        match = re.match(r"id:(0+)(\d+),", input_name)
        input_id = int(match.groups()[1])
        seconds = id_to_time[input_id] - start_time

        #print("%d: %s - %d" % (input_id, input_file, seconds))
        input_id_time.append([input_file, input_id, seconds])
        #yield (input_file, input_id, int(timestamp))
    return input_id_time


def kafl_workdir_iterator(work_dir):
    input_id_time = list()
    start_time = time.time()
    for stats_file in glob.glob(work_dir + "/slave_stats_*"):
        if not stats_file:
            return None
        slave_stats = msgpack.unpackb(read_binary_file(stats_file), raw=False, strict_map_key=False)
        start_time = min(start_time, slave_stats['start_time'])
    
    # enumerate inputs from corpus/ and match against metainfo in metadata/
    for input_file in glob.glob(work_dir + "/corpus/*/*"):
        if not input_file:
            return None
        input_id = os.path.basename(input_file).replace("payload_", "")
        meta_file = work_dir + "/metadata/node_{}".format(input_id)
        metadata = msgpack.unpackb(read_binary_file(meta_file), raw=False, strict_map_key=False)
    
        seconds = metadata["info"]["time"] - start_time
        nid = metadata["id"]
    
        #print("%s;%d" % (input_file, timestamp))
        input_id_time.append([input_file, nid, seconds])
        #yield (input_file, nid, timestamp)

    return input_id_time


def get_inputs_by_time(data_dir):
    # check if data_dir is kAFL or AFL type, then assemble sorted list of inputs/input IDs over time
    if (os.path.exists(data_dir + "/fuzzer_stats") and
        os.path.exists(data_dir + "/fuzz_bitmap") and
        os.path.exists(data_dir + "/plot_data") and
        os.path.isdir(data_dir + "/queue")):
            input_data = afl_workdir_iterator(data_dir)

    elif (os.path.isdir(data_dir + "/corpus/regular") and
        os.path.isdir(data_dir + "/metadata")):
            input_data = kafl_workdir_iterator(data_dir)
    else:
        print_note("Unrecognized target directory type «%s». Exit." % data_dir)
        sys.exit()
    
    input_data.sort(key=itemgetter(2))
    return input_data


def generate_traces(config, input_list):

    is_purge = config.argument_values['purge']
    work_dir = config.argument_values['work_dir']
    data_dir = config.argument_values["input"]
    trace_dir = data_dir + "/traces/"

    if data_dir == work_dir:
        print_note("Workdir must be separate from input/data dir. Aborting.")
        return None

    prepare_working_dir(config.argument_values['work_dir'], is_purge)

    if os.path.exists(trace_dir):
        print_note("Input data_dir already has a traces/ subdir. Skipping trace generation..\n")
        return trace_dir

    # real deal. delete trace dir if it exists and (re-)create traces
    shutil.rmtree(trace_dir, ignore_errors=True)
    os.makedirs(trace_dir)

    # TODO What is the effect of not defining a trace region? will it trace?
    if not config.argument_values['ip0']:
        print_warning("No trace region configured!")

    if os.path.exists(work_dir + "redqueen_workdir_1337"):
        print_fail("Leftover files from 1337 instance. This should not happen.")
        return None

    q = qemu(1337, config, debug_mode=False)
    if not q.start():
        print_fail("Could not start Qemu. Exit.")
        return None

    start = time.time()

    try:
        for input_path, nid, timestamp in input_list:
            print("Processing: %s" % input_path)

            q.set_payload(read_binary_file(input_path))
            exec_res = q.execute_in_trace_mode(timeout_detection=False)

            if not exec_res:
                print_note("Failed to execute input %s. Continuing anyway..." % input_path)
                q.restart()
                continue

            # TODO: reboot by default, persistent by option
            if exec_res.is_crash():
                q.restart()

            with open(work_dir + "/redqueen_workdir_1337/pt_trace_results.txt", 'rb') as f_in:
                with lz4.LZ4FrameFile(trace_dir + os.path.basename(input_path) + ".lz4", 'wb', compression_level=lz4.COMPRESSIONLEVEL_MINHC) as f_out:
                        shutil.copyfileobj(f_in, f_out)

    except:
        raise
    finally:
        q.async_exit()

    end = time.time()
    print("Time taken: %.2fs" % (end - start))
    return trace_dir


def plot_bbs_from_traces(trace_dir, input_list):

    input_to_new_bbs = list()
    trace_parser = TraceParser()

    for input_path, nid, timestamp in input_list:
        filename = os.path.basename(input_path) + ".lz4"
        new_bbs, new_edges = trace_parser.get_cov_by_trace(trace_dir + filename, nid)
        input_to_new_bbs.append([timestamp, new_bbs, new_edges])

    total_bbs = 0
    total_edges = 0

    # should be already sorted b/c get_cov_by_trace() expects sorted inputs
    input_to_new_bbs.sort(key=itemgetter(0))

    # write output to .csv
    plot_file = trace_dir + "coverage.csv"
    print(" Writing coverage data to %s..." % plot_file)
    with open(plot_file, 'w') as f:
        for item in input_to_new_bbs:
            total_bbs += item[1]
            total_edges += item[2]
            plot_data = "%d;%d;%d\n" % (item[0], total_bbs, total_edges)
            f.write(plot_data)

    print(" Processed %d traces with a total of %d BBs (%d edges)." % (len(input_to_new_bbs), total_bbs, total_edges))



def main():

    KAFL_ROOT = os.path.dirname(os.path.realpath(__file__)) + "/"
    KAFL_CONFIG = KAFL_ROOT + "kafl.ini"

    print("<< " + common.color.BOLD + common.color.OKGREEN +
            " kAFL Coverage Analyzer " + common.color.ENDC + ">>\n")

    if not self_check(KAFL_ROOT):
        return -1

    config = DebugConfiguration(KAFL_CONFIG)
    if not post_self_check(config):
        return -1

    verbose = config.argument_values['v']
    if verbose:
        enable_logging(config.argument_values["work_dir"])

    data_dir = config.argument_values["input"]

    print(" Scanning target data_dir »%s«..." % data_dir )
    input_list = get_inputs_by_time(data_dir)
    trace_dir = generate_traces(config, input_list)
    
    if not trace_dir:
        return -1
    
    plot_bbs_from_traces(trace_dir, input_list)


if __name__ == "__main__":
    main()
