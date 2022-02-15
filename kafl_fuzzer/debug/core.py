# Copyright 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

import os
import shutil
import time
from sys import stdout
from threading import Thread

import mmh3

import kafl_fuzzer.common.color as color
from kafl_fuzzer.common.rand import rand
from kafl_fuzzer.common.logger import init_logger, logger
from kafl_fuzzer.common.config import DebugConfiguration
from kafl_fuzzer.common.self_check import post_self_check
from kafl_fuzzer.common.util import prepare_working_dir, read_binary_file, qemu_sweep
from kafl_fuzzer.worker.execution_result import ExecutionResult
from kafl_fuzzer.worker.qemu import qemu
from kafl_fuzzer.technique.redqueen import parser
from kafl_fuzzer.technique.redqueen.hash_fix import HashFixer
from kafl_fuzzer.technique.redqueen.workdir import RedqueenWorkdir

REFRESH = 0.25


def hexdump(src, length=16):
    FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])
    lines = []
    for c in range(0, len(src), length):
        chars = src[c:c + length]
        hex = ' '.join(["%02x" % x for x in chars])
        printable = ''.join(["%s" % ((x <= 127 and FILTER[x]) or '.') for x in chars])
        lines.append("%04x  %-*s  %s\n" % (c, length * 3, hex, printable))
    return ''.join(lines)


def benchmark(config):
    logger.info("Starting benchmark...")
    payload_file = config.argument_values["input"]
    payload = read_binary_file(payload_file)

    q = qemu(1337, config, debug_mode=False)
    q.start()
    try:
        q.set_payload(payload)
        res = q.send_payload()

        logger.info("Payload hash: " + str(res.hash()))
        logger.info("Payload exit: " + res.exit_reason)
        logger.info("Calibrating...")

        start = time.time()
        iterations = 0
        while (time.time() - start < 1):
            q.set_payload(payload)
            q.send_payload()
            iterations += 1

        #logger.info("Calibrate to run at %d execs/s..." % iterations)
        rounds = 0
        runtime = 0
        total = 0
        while True:
            start = time.time()
            for _ in range(int(REFRESH*iterations)):
                q.set_payload(payload)
                q.send_payload()
            rounds += 1
            runtime = time.time() - start
            total += runtime
            print(color.FLUSH_LINE + "Performance: %.2f execs/s" % (iterations / runtime), end='\r')
    except Exception as e:
        logger.warn(repr(e))
    except KeyboardInterrupt:
        pass
    finally:
        print("\nPerformance Average: %.2f execs/s\n" % (rounds*iterations/total))
        q.shutdown()
    return 0


def gdb_session(config, qemu_verbose=True, notifiers=True):

    #from pprint import pprint
    payload_file = config.argument_values["input"]
    resume = config.argument_values["resume"]

    config.argument_values["gdbserver"] = True
    q = qemu(1337, config, notifiers=notifiers, resume=resume)

    logger.info("Starting Qemu + GDB with payload %s" % payload_file)
    logger.info("Connect with gdb to release guest from reset (localhost:1234)")
    try:
        if q.start():
            q.set_payload(read_binary_file(payload_file))
            result = q.debug_payload()
            logger.info("Thank you for playing.")
            #pprint(result._asdict())
    finally:
        logger.info("Shutting down..")
        q.async_exit()

def execute_once(config, qemu_verbose=False, notifiers=True):
    payload_file = config.argument_values["input"]
    resume = config.argument_values["resume"]
    null_hash = ExecutionResult.get_null_hash(config.config_values['BITMAP_SHM_SIZE'])

    logger.info("Execute payload %s.. " % payload_file)

    q = qemu(1337, config, debug_mode=False, notifiers=notifiers, resume=resume)
    assert q.start(), "Failed to start Qemu?"


    store_traces = config.argument_values["trace"]
    if store_traces:
        trace_out = config.argument_values["work_dir"] + "/redqueen_workdir_1337/pt_trace_results.txt"
        trace_dir  = config.argument_values["work_dir"] + "/traces/"

    payload = read_binary_file(payload_file)

    payload_size_limit = config.config_values['PAYLOAD_SHM_SIZE'] - 8
    if len(payload) > payload_size_limit:
        payload = payload[:payload_size_limit]

    q.set_payload(payload)
    #q.send_payload() ## XXX first run has different trace?!
    if store_traces:
        result = q.execute_in_trace_mode()
    else:
        result = q.send_payload()

    print("Exit reason: %s" % result.exit_reason)

    current_hash = result.hash()
    logger.info("Feedback Hash: " + current_hash)
    if null_hash == current_hash:
        logger.warn("Null hash returned!")

    if store_traces:
        shutil.copyfile(trace_out, trace_dir + "/trace_%s_%s.txt" % (os.path.basename(payload_file),current_hash))

    q.shutdown()
    return 0

def debug_execution(config, execs, qemu_verbose=False, notifiers=True):
    logger.info("Starting debug execution...(%d rounds)" % execs)

    payload_file = config.argument_values["input"]
    resume = config.argument_values["resume"]
    null_hash = ExecutionResult.get_null_hash(config.config_values['BITMAP_SHM_SIZE'])

    q = qemu(1337, config, debug_mode=True, notifiers=notifiers, resume=resume)
    assert q.start(), "Failed to start Qemu?"

    payload = read_binary_file(payload_file)
    payload_size_limit = config.config_values['PAYLOAD_SHM_SIZE'] - 8

    if len(payload) > payload_size_limit:
        payload = payload[:payload_size_limit]

    start = time.time()
    for i in range(execs):
        logger.info("Launching payload %d/%d.." % (i+1,execs))
        if i % 3 == 0:
            q.set_payload(payload)
        # time.sleep(0.01 * rand.int(0, 9))
        # a = str(q.send_payload())
        # hexdump(a)
        result = q.send_payload()

        current_hash = result.hash()
        logger.info("Feedback Hash: " + current_hash)
        if null_hash == current_hash:
            logger.warn("Null hash returned!")

        if result.is_crash():
            q.reload()

    q.shutdown()
    end = time.time()
    logger.info("Performance: " + str(execs / (end - start)) + "t/s")

    return 0

def debug_non_det(config, max_execs=0):
    logger.info("Starting non-deterministic...")

    delay = 0
    payload_file = config.argument_values["input"]
    resume = config.argument_values["resume"]
    null_hash = ExecutionResult.get_null_hash(config.config_values['BITMAP_SHM_SIZE'])

    assert os.path.isfile(payload_file), "Provided -input argument must be a file."
    assert "ip0" in config.argument_values, "Must set -ip0 range in order to obtain PT traces."
    payload = read_binary_file(payload_file)

    q = qemu(1337, config, debug_mode=False, resume=resume)
    assert q.start(), "Failed to launch Qemu."

    q.set_timeout(0)

    store_traces = config.argument_values["trace"]
    if store_traces:
        trace_out = config.argument_values["work_dir"] + "/redqueen_workdir_1337/pt_trace_results.txt"
        trace_dir  = config.argument_values["work_dir"] + "/noise/"
        os.makedirs(trace_dir, exist_ok=True)

    payload_size_limit = config.config_values['PAYLOAD_SHM_SIZE'] - 8

    if len(payload) > payload_size_limit:
        payload = payload[:payload_size_limit]

    hash_value = None
    first_hash = None
    hashes = dict()
    try:
        q.set_payload(payload)

        ## XXX first run has different trace?!
        #if store_traces: 
        #    exec_res = q.execute_in_trace_mode()
        #else:
        #    exec_res = q.send_payload()

        time.sleep(delay)

        if store_traces: 
            exec_res = q.execute_in_trace_mode()
        else:
            exec_res = q.send_payload()

        first_hash = exec_res.hash()
        hashes[first_hash] = 1

        logger.info("Null Hash:  " + null_hash)
        logger.info("First Hash: " + first_hash)

        if store_traces:
            shutil.copyfile(trace_out, trace_dir + "/trace_%s_%s.txt" % (os.path.basename(payload_file),first_hash))

        total = 0
        iterations = 1
        hash_mismatch = 0
        time.sleep(delay)
        while max_execs == 0 or iterations <= max_execs:
            start = time.time()
            execs = 0
            while (time.time() - start < REFRESH):
                # restart Qemu every time?
                #q.async_exit()
                #q = qemu(0, config, debug_mode=False, resume=resume)
                #assert q.start(), "Failed to launch Qemu."
                q.set_payload(payload)
                time.sleep(delay)
                if store_traces: 
                    exec_res = q.execute_in_trace_mode()
                else:
                    exec_res = q.send_payload()

                if exec_res.is_crash():
                    logger.info("\nExit reason `%s` - restarting..." % exec_res.exit_reason)
                    q.reload()

                time.sleep(delay)
                hash_value = exec_res.hash()
                if hash_value in hashes:
                    hashes[hash_value] = hashes[hash_value] + 1
                else:
                    hashes[hash_value] = 1
                    if store_traces:
                        shutil.copyfile(trace_out, trace_dir + "/trace_%s_%s.txt" % (os.path.basename(payload_file), hash_value))
                if hash_value != first_hash:
                    hash_mismatch += 1
                execs += 1
            runtime = time.time() - start
            total += runtime
            iterations += execs
            noise = hash_mismatch*100/iterations
            code = color.FAIL if (len(hashes) != 1) else color.OKGREEN
            print(color.FLUSH_LINE +
                    "Perf: %7.2f execs/s, Execs: %7d, Mismatches: %s %4d %s, Noise %3d" %
                    (execs / runtime, iterations, code, hash_mismatch, color.ENDC, noise), end='\r')

    except Exception as e:
        logger.warn(repr(e))
    except KeyboardInterrupt:
        pass
    finally:
        print("\nOverall Perf: %7.2f execs/s, Execs: %7d, Mismatches: %s %4d %s, Noise %3d" %
                (iterations / total, iterations, code, hash_mismatch, color.ENDC, noise))
        q.shutdown()

    for h in hashes.keys():
        if h == first_hash:
            logger.info("* %s: %03d" % (h, hashes[h]))
        else:
            logger.info("  %s: %03d" % (h, hashes[h]))

    return 0


thread_done = False
first_line = True


def requeen_print_state(qemu):
    global first_line
    if not first_line:
        stdout.write(color.MOVE_CURSOR_UP(1))
    else:
        first_line = False

    try:
        size_a = str(os.stat(qemu.redqueen_workdir.redqueen()).st_size)
    except:
        size_a = "0"

    try:
        size_b = str(os.stat(qemu.redqueen_workdir.symbolic()).st_size)
    except:
        size_b = "0"

    stdout.write(color.FLUSH_LINE + "Log Size:\t" + size_a + " Bytes\tSE Size:\t" + size_b + " Bytes\n")
    stdout.flush()


def redqueen_dbg_thread(q):
    global thread_done, first_line
    while not thread_done:
        time.sleep(0.5)
        if not thread_done:
            requeen_print_state(q)


def redqueen_dbg(config, qemu_verbose=False):
    global thread_done
    logger.info("Starting Redqueen debug...")

    q = qemu(1337, config, debug_mode=True)
    q.start()
    payload = read_binary_file(config.argument_values["input"])
    # q.set_payload(payload)

    if os.path.exists("patches"):
        shutil.copyfile("patches", "/tmp/redqueen_workdir_1337/redqueen_patches.txt")

    start = time.time()

    thread = Thread(target=lambda: redqueen_dbg_thread(q))
    thread.start()
    result = q.execute_in_redqueen_mode(payload, debug_mode=True)
    thread_done = True
    thread.join()
    requeen_print_state(q)
    end = time.time()

    if result:
        logger.info("Execution succeded!")
    else:
        logger.error("Execution failed!")

    logger.info("Time: " + str(end - start) + "t/s")

    num_muts, muts = parser.parse_rq_data(
        open("/tmp/kafl_debug_workdir/redqueen_workdir_1337/redqueen_results.txt").read(), payload)
    count = 0
    for offset in muts:
        for lhs in muts[offset]:
            for rhs in muts[offset][lhs]:
                count += 1
                logger.info(offset, lhs, rhs)
    logger.info(count)

    return 0


def verify_dbg(config, qemu_verbose=False):
    global thread_done

    logger.info("Starting...")

    rq_state = RedqueenState()
    workdir = RedqueenWorkdir(1337)

    if os.path.exists("patches"):
        with open("patches", "r") as f:
            for x in f.readlines():
                rq_state.add_candidate_hash_addr(int(x, 16))
    if not rq_state.get_candidate_hash_addrs():
        logger.warn("No patches configured\nMaybe add ./patches with addresses to patch.")
    else:
        logger.info("OK: got patches %s\n", rq_state.get_candidate_hash_addrs())
    q = qemu(1337, config, debug_mode=True)

    logger.info("using qemu command:\n%s\n" % q.cmd)

    q.start()

    orig_input = read_binary_file(config.argument_values["input"])
    q.set_payload(orig_input)

    # result = q.send_payload()

    with open(q.redqueen_workdir.whitelist(), "w") as w:
        with open(q.redqueen_workdir.patches(), "w") as p:
            for addr in rq_state.get_candidate_hash_addrs():
                addr = hex(addr).rstrip("L").lstrip("0x") + "\n"
                w.write(addr)
                p.write(addr)

    logger.info("RUN WITH PATCHING:")
    bmp1 = q.send_payload(apply_patches=True)

    logger.info("\nNOT PATCHING:")
    bmp2 = q.send_payload(apply_patches=False)

    if bmp1 == bmp2:
        logger.warn("Patches don't seem to change anything, are checksums present?")
    else:
        logger.info("OK: bitmaps are distinct")

    q.soft_reload()

    hash = HashFixer(q, rq_state)

    logger.info("fixing hashes")
    fixed_payload = hash.try_fix_data(orig_input)
    if fixed_payload:

        logger.info("%s\n", repr("".join(map(chr, fixed_payload))))

        q.set_payload(fixed_payload)

        bmp3 = q.send_payload(apply_patches=False)

        if bmp1 == bmp3:
            logger.info("CONGRATZ, BITMAPS ARE THE SAME, all cmps fixed\n")
        else:
            logger.warn("After fixing cmps, bitmaps differ\n")
    else:
        logger.error("couldn't fix payload\n")

    start = time.time()
    return 0


def start(config):

    assert prepare_working_dir(config), "Failed to create work_dir %s" % config.argument_values["work_dir"]

    if not post_self_check(config):
        return -1

    work_dir = config.argument_values["work_dir"]
    init_logger(config)

    # Without -ip0, Qemu will not active PT tracing and Redqueen will not
    # attempt to handle debug traps. This is a requirement for modes like gdb.
    if not config.argument_values['ip0']:
        logger.warn("No trace region configured! Intel PT disabled!")

    max_execs = config.argument_values['n']

    try:
        # TODO: noise, benchmark, trace are working, others untested
        mode = config.argument_values['action']
        if   (mode == "noise"):         debug_non_det(config, max_execs)
        elif (mode == "benchmark"):     benchmark(config)
        elif (mode == "gdb"):           gdb_session(config, qemu_verbose=True)
        elif (mode == "single"):        execute_once(config, qemu_verbose=False)
        elif (mode == "trace"):         debug_execution(config, max_execs)
        elif (mode == "trace-qemu"):    debug_execution(config, max_execs, qemu_verbose=True)
        elif (mode == "printk"):        debug_execution(config, 1, qemu_verbose=True, notifiers=False)
        elif (mode == "redqueen"):      redqueen_dbg(config, qemu_verbose=False)
        elif (mode == "redqueen-qemu"): redqueen_dbg(config, qemu_verbose=True)
        elif (mode == "verify"):        verify_dbg(config, qemu_verbose=True)
        else:
            logger.error("Unknown debug mode. Exit")
        logger.info("Done. Check logs for details.")
    except KeyboardInterrupt:
        logger.info("Received Ctrl-C, aborting...")
    except Exception as e:
        raise e

    time.sleep(0.2) # Qemu can take a moment to exit
    qemu_sweep("Any remaining qemu instances should be GC'ed on exit:")

    return 0
