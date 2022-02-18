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
import re
import signal
import multiprocessing as mp
import subprocess
import tempfile
from operator import itemgetter

import msgpack
import lz4.frame as lz4
from tqdm import trange, tqdm
from math import ceil

import kafl_fuzzer.common.color as color
from kafl_fuzzer.common.config import DebugConfiguration
from kafl_fuzzer.common.self_check import self_check, post_self_check
from kafl_fuzzer.common.logger import init_logger, logger
from kafl_fuzzer.common.util import prepare_working_dir, read_binary_file, qemu_sweep, print_banner
from kafl_fuzzer.worker.execution_result import ExecutionResult
from kafl_fuzzer.worker.qemu import qemu

import json
import csv

null_hash = None

class TraceParser:

    def __init__(self, trace_dir):
        self.trace_dir = trace_dir
        self.known_bbs = set()
        self.known_edges = set()
        self.trace_results = list()


    @staticmethod
    def parse_trace_file(trace_file):
        if not os.path.isfile(trace_file):
            logger.warn("Could not find trace file %s, skipping.." % trace_file)
            return None

        bbs = set()
        edges = dict()
        with lz4.LZ4FrameFile(trace_file, 'rb') as f:
            for m in re.finditer("([\da-f]+),([\da-f]+)", f.read().decode()):
                edges["%s,%s" % (m.group(1), m.group(2))] = 1
                bbs.add(m.group(1))
                bbs.add(m.group(2))

        return {'bbs': bbs, 'edges': edges}

    def parse_trace_list(self, nproc, input_list):
        trace_files = list()
        timestamps = list()

        for input_file, nid, timestamp in input_list:
            #trace_file = self.trace_dir + os.path.basename(input_file) + ".lz4"
            #trace_file = "%s/cov_%05d.lst.lz4" % (trace_dir, nid)
            trace_file = "%s/fuzz_%05d.lst.lz4" % (self.trace_dir, nid)
            if os.path.exists(trace_file):
                trace_files.append(trace_file)
                timestamps.append(timestamp)

        with mp.Pool(nproc) as pool:
            self.trace_results = zip(timestamps,
                                     pool.map(TraceParser.parse_trace_file, trace_files))

    def coverage_totals(self):
        unique_bbs = set()
        unique_edges = dict()
        unique_traces = 0

        for _, findings in self.trace_results:
            if findings:
                unique_traces += 1
                unique_bbs.update(findings['bbs'])
                edges = findings['edges']
                for edge,num in edges:
                    if edge in unique_edges:
                        unique_edges[edge] += edges[edge]
                    else:
                        unique_edges[edge] = num

        logger.info(" Processed %d traces with a total of %d BBs (%d edges)." \
                % (unique_traces, len(unique_bbs), len(unique_edges)))

        return unique_edges, unique_bbs

    def gen_reports(self):
        unique_bbs = set()
        unique_edges = dict()
        input_to_new_bbs = list()

        plot_file = self.trace_dir + "/coverage.csv"
        edges_file = self.trace_dir + "/edges_uniq.lst"

        with open(plot_file, 'w') as f:
            num_bbs = 0
            num_edges = 0
            num_traces = 0
            for timestamp, findings in self.trace_results:
                if not findings: continue

                new_bbs = len(findings['bbs'] - unique_bbs)
                new_edges = len(set(findings['edges']) - set(unique_edges))
                unique_bbs.update(findings['bbs'])
                edges = findings['edges']
                for edge,num in edges.items():
                    if edge in unique_edges:
                        unique_edges[edge] += edges[edge]
                    else:
                        unique_edges[edge] = num

                num_traces += 1
                num_bbs += new_bbs
                num_edges += new_edges
                f.write("%d;%d;%d\n" % (timestamp, num_bbs, num_edges))
        
        with open(edges_file, 'w') as f:
            for edge,num in unique_edges.items():
                f.write("%s,%x\n" % (edge,num))

        logger.info(" Processed %d traces with a total of %d BBs (%d edges)." \
                % (num_traces, num_bbs, num_edges))

        logger.info(" Plot data written to %s" % plot_file)
        logger.info(" Unique edges written to %s" % edges_file)

        return unique_edges, unique_bbs


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

        input_id_time.append([input_file, input_id, seconds])
        #yield (input_file, input_id, int(timestamp))
    return input_id_time


def kafl_workdir_iterator(work_dir):
    input_id_time = list()
    start_time = time.time()
    for stats_file in glob.glob(work_dir + "/worker_stats_*"):
        if not stats_file:
            return None
        worker_stats = msgpack.unpackb(read_binary_file(stats_file), strict_map_key=False)
        start_time = min(start_time, worker_stats['start_time'])

    # enumerate inputs from corpus/ and match against metainfo in metadata/
    # TODO: Tracing crashes/timeouts has minimal overall improvement ~1-2%
    # Probably want to make this optional, and only trace a small sample
    # of non-regular payloads by default?
    for input_file in glob.glob(work_dir + "/corpus/[rck]*/*"):
        if not input_file:
            return None
        input_id = os.path.basename(input_file).replace("payload_", "")
        meta_file = work_dir + "/metadata/node_{}".format(input_id)
        metadata = msgpack.unpackb(read_binary_file(meta_file), strict_map_key=False)

        seconds = metadata["info"]["time"] - start_time
        nid = metadata["id"]

        input_id_time.append([input_file, nid, seconds])

    return input_id_time

def get_inputs_by_time(data_dir):
    # check if data_dir is kAFL or AFL type, then assemble sorted list of inputs/input IDs over time
    if (os.path.exists(data_dir + "/fuzzer_stats") and
        os.path.exists(data_dir + "/fuzz_bitmap") and
        os.path.exists(data_dir + "/plot_data") and
        os.path.isdir(data_dir + "/queue")):
            input_data = afl_workdir_iterator(data_dir)

    elif (os.path.exists(data_dir + "/stats") and
          os.path.isdir(data_dir + "/corpus/regular") and
          os.path.isdir(data_dir + "/metadata")):
            input_data = kafl_workdir_iterator(data_dir)
    else:
        logger.error("Unrecognized target directory type «%s». Exit." % data_dir)
        sys.exit()

    # timestamps may be off slightly but payload IDs are strictly ordered by kAFL Manager
    input_data.sort(key=itemgetter(2))
    return input_data

def graceful_exit(workers):
    for w in workers:
        w.terminate()

    logger.info("Waiting for Worker to shutdown...")
    time.sleep(1)

    while len(workers) > 0:
        for w in workers:
            if w and w.exitcode is None:
                logger.info("Still waiting on %s (pid=%d)..  [hit Ctrl-c to abort..]" % (w.name, w.pid))
                w.join(timeout=1)
            else:
                workers.remove(w)

def generate_traces(config, nproc, input_list):

    trace_dir = config.argument_values["input"] + "/traces/"

    # TODO What is the effect of not defining a trace region? will it trace?
    if not config.argument_values['ip0']:
        logger.warn("No trace region configured!")
        return None

    os.makedirs(trace_dir, exist_ok=True)

    work_queue = list()
    for input_path, nid, _ in input_list:

        # FIXME: should fully separate decode step to decide more flexibly which
        # type of traces to decode all of these can be relevant: runtime 'fuzz',
        # 'cov' (separate kafl_cov) or noise (additional traces generated from
        # noisy targets)
        # generate own cov_NNNNN.bin files for decoding
        dump_file  = "%s/cov_%05d.bin.lz4" % (trace_dir, nid)
        trace_file = "%s/cov_%05d.lst.lz4" % (trace_dir, nid)
        # pickup existing fuzz_NNNNN.bin or generate them here for decoding
        dump_file  = "%s/fuzz_%05d.bin.lz4" % (trace_dir, nid)
        trace_file = "%s/fuzz_%05d.lst.lz4" % (trace_dir, nid)
        work_queue.append((input_path, dump_file, trace_file))

    chunksize=ceil(len(work_queue)/nproc)
    offset = 0
    workers = list()

    try:
        for pid in range(nproc):
            sublist = work_queue[offset:offset+chunksize]
            offset += chunksize
            if len(sublist) > 0:
                worker = mp.Process(target=generate_traces_worker, args=(config, pid, sublist))
                worker.start()
                workers.append(worker)

        for worker in workers:
            while worker.is_alive():
                time.sleep(2)
            if worker.exitcode != 0:
                return None

    except KeyboardInterrupt:
        logger.info("Received Ctrl-C, closing Workers...")
        return None
    except Exception:
        return None
    finally:
        graceful_exit(workers)

    return trace_dir

def generate_traces_worker(config, pid, work_queue):

    dump_mode = True;

    def sigterm_handler(signal, frame):
        if q:
            q.async_exit()
        sys.exit(0)

    pname = mp.current_process().name
    pnum =   mp.current_process()._identity[0]

    ptdump_path = config.config_values['PTDUMP_LOCATION']

    if config.argument_values['resume']:
        # spawn worker in same workdir, picking up snapshot + page_cache
        config.argument_values['purge'] = False # not needed?
        qemu_id = int(pnum) # get unique qemu ID != {0,1337}
    else:
        # spawn worker in separate workdir, booting a new VM state
        config.argument_values['work_dir'] += "_%s" % pname
        config.argument_values['purge'] = True # not needed?
        qemu_id = 1337 # debug instance

    prepare_working_dir(config)

    work_dir = config.argument_values['work_dir']
    trace_dir = config.argument_values["input"] + "/traces/"

    signal.signal(signal.SIGTERM, sigterm_handler)
    os.setpgrp()

    # FIXME: really ugly switch between -trace and -dump_pt
    if dump_mode:
        print("Tracing in '-trace' mode..")
        # new dump_pt mode - translate to edge trace in separate step
        config.argument_values['trace'] = True
        config.argument_values['trace_cb'] = False
    else:
        # traditional -trace mode - more noisy and no bitmap to check
        print("Tracing in legacy '-trace_cb' mode..")
        config.argument_values['trace'] = False
        config.argument_values['trace_cb'] = True

    q = qemu(qemu_id, config, debug_mode=False)
    if not q.start():
        logger.error("%s: Could not start Qemu. Exit." % pname)
        return None

    pbar = tqdm(total=len(work_queue), desc=pname, dynamic_ncols=True, smoothing=0.1, position=pid+1)

    f = tempfile.NamedTemporaryFile(delete=False)
    tmpfile = f.name
    f.close()

    try:
        for input_path, dump_file, trace_file in work_queue:
            print("\nProcessing %s.." % os.path.basename(input_path))

            if dump_mode:
                # -trace mode (pt dump)
                if not os.path.exists(dump_file):
                    qemu_file = work_dir + "/pt_trace_dump_%d" % qemu_id
                    if simple_trace_run(q, read_binary_file(input_path), q.send_payload):
                        with open(qemu_file, 'rb') as f_in:
                            with lz4.LZ4FrameFile(dump_file, 'wb', compression_level=lz4.COMPRESSIONLEVEL_MINHC) as f_out:
                                shutil.copyfileobj(f_in, f_out)

                if not os.path.exists(trace_file):
                    with tempfile.NamedTemporaryFile(delete=False) as pt_tmp:
                        with lz4.LZ4FrameFile(dump_file, 'rb') as pt_dump_lz4:
                                shutil.copyfileobj(pt_dump_lz4, pt_tmp)
                        pt_tmp.close()

                        cmd = [ ptdump_path, work_dir + "/page_cache", pt_tmp.name, tmpfile ]
                        for i in range(2):
                            key = "ip" + str(i)
                            if key in config.argument_values and config.argument_values[key]:
                                ip_start = hex(config.argument_values[key][0]).replace("L", "")
                                ip_end = hex(config.argument_values[key][1]).replace("L", "")
                                cmd += [ ip_start, ip_end ]

                        try:
                            subprocess.run(cmd, timeout=180)
                            os.unlink(pt_tmp.name)
                        except subprocess.TimeoutExpired as e:
                            print(e)
                            os.unlink(pt_tmp.name)
                            continue

                        with open(tmpfile, 'rb') as f_in:
                            with lz4.LZ4FrameFile(trace_file, 'wb', compression_level=lz4.COMPRESSIONLEVEL_MINHC) as f_out:
                                shutil.copyfileobj(f_in, f_out)

            else:
                # -trace_cb mode (libxdc callback)
                if not os.path.exists(trace_file):
                    qemu_file = work_dir + "/redqueen_workdir_%d/pt_trace_results.txt" % qemu_id
                    if simple_trace_run(q, read_binary_file(input_path), q.send_payload):
                        with open(qemu_file, 'rb') as f_in:
                            with lz4.LZ4FrameFile(trace_file, 'wb', compression_level=lz4.COMPRESSIONLEVEL_MINHC) as f_out:
                                shutil.copyfileobj(f_in, f_out)
            pbar.update()
    except Exception:
        q.async_exit()
        raise
    finally:
        os.unlink(tmpfile)
    q.shutdown()


def simple_trace_run(q, payload, send_func):
    global null_hash
    q.set_payload(payload)
    q.set_trace_mode(True)
    exec_res = send_func()
    q.set_trace_mode(False)

    if not exec_res:
        print("Failed to execute. Continuing anyway...\n")
        assert(q.restart())
        return None

    if exec_res.is_crash():
        q.reload()

    return exec_res

def funky_trace_run(q, input_path, retry=1):
    validations = 12
    confirmations = 0

    payload = read_binary_file(input_path)

    hashes = dict()
    for _ in range(validations):
        res = simple_trace_run(q, payload)
        if not res:
            return None

        # skip crahses and timeouts as they tend to be slow
        if res.is_crash():
            return res

        h = res.hash()
        if h == null_hash:
            continue

        if  h in hashes:
            hashes[h] += 1
        else:
            hashes[h] = 1

        # break early if we have a winner, with trace stored to temp file
        if hashes[h] >= 0.5*validations:
            return res

    #print("Failed to get majority trace (retry=%d)\nHashes: %s\n" % (retry, str(hashes)))

    if retry > 0:
        q.restart()
        time.sleep(1)
        return funky_trace_run(q, input_path, retry=retry-1)

    return None


def main():
    global null_hash

    KAFL_ROOT = os.path.dirname(os.path.realpath(__file__)) + "/kafl_fuzzer/"
    KAFL_CONFIG = KAFL_ROOT + "kafl.ini"

    print_banner("kAFL Coverage Analyzer")

    if not self_check(KAFL_ROOT):
        return -1

    config = DebugConfiguration(KAFL_CONFIG)
    if not post_self_check(config):
        return -1

    init_logger(config)

    data_dir = config.argument_values["input"]

    null_hash = ExecutionResult.get_null_hash(config.config_values['BITMAP_SHM_SIZE'])

    nproc = min(config.argument_values["p"], os.cpu_count())
    logger.info("Using %d/%d cores..." % (nproc, os.cpu_count()))

    logger.info("Scanning target data_dir »%s«..." % data_dir)
    input_list = get_inputs_by_time(data_dir)

    start = time.time()
    logger.info("Generating traces...")
    trace_dir = generate_traces(config, nproc, input_list)
    end = time.time()
    logger.info("\n\nDone. Time taken: %.2fs\n" % (end - start))

    if not trace_dir:
        return -1

    logger.info("Parsing traces...")
    trace_parser = TraceParser(trace_dir)
    trace_parser.parse_trace_list(nproc, input_list)
    # TODO: store parsed traces here here and share class with other tools

    # generate basic summary files
    trace_parser.gen_reports()

if __name__ == "__main__":
    main()
    qemu_sweep("Detected potential qemu zombies, please kill -9:")
