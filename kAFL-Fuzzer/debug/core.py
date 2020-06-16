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

import os
import shutil
import time
from sys import stdout
from threading import Thread

import mmh3

import common.color
from common.config import DebugConfiguration
from common.debug import log_info, enable_logging
from common.qemu import qemu
from common.safe_syscall import safe_print
from common.self_check import post_self_check
from common.util import prepare_working_dir
from debug.trace import TraceParser
# from fuzzer.state import RedqueenState
from fuzzer.technique.redqueen import parser
from fuzzer.technique.redqueen.hash_fix import HashFixer
from fuzzer.technique.redqueen.workdir import RedqueenWorkdir

REFRESH = 0.25


def hexdump(src, length=16):
    print("YO")
    FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])
    lines = []
    for c in xrange(0, len(src), length):
        chars = src[c:c + length]
        hex = ' '.join(["%02x" % ord(x) for x in chars])
        printable = ''.join(["%s" % ((ord(x) <= 127 and FILTER[ord(x)]) or '.') for x in chars])
        lines.append("%04x  %-*s  %s\n" % (c, length * 3, hex, printable))
    return ''.join(lines)


def benchmark(config):
    log_info("Starting...")

    q = qemu(1337, config, debug_mode=False)
    q.start(verbose=False)
    q.set_payload(open(config.argument_values["payload"][0]).read())
    print(q.send_payload().hash())
    try:
        while True:
            start = time.time()
            execs = 0
            # for i in range(execs):
            while (time.time() - start < REFRESH):
                q.set_payload(open(config.argument_values["payload"][0]).read())
                q.send_payload()
                execs += 1
            end = time.time()
            # print("Performance: " + str(execs/(end - start)) + "t/s")
            stdout.write(common.color.FLUSH_LINE + "Performance: " + str(execs / (end - start)) + "t/s")
            stdout.flush()
    except:
        print("\nExit")

    q.__del__()
    try:
        for i in range(512):
            if os.path.exists("/tmp/kAFL_printf.txt." + str(i)):
                os.remove("/tmp/kAFL_printf.txt." + str(i))
            else:
                break
    except:
        pass
    return 0


def debug_execution(config, execs, qemu_verbose=False, notifiers=True):
    log_info("Starting...")

    zero_hash = mmh3.hash64(("\x00" * config.config_values['BITMAP_SHM_SIZE']))
    q = qemu(1337, config, debug_mode=True, notifiers=notifiers)
    q.start(verbose=qemu_verbose)
    q.set_payload(open(config.argument_values["payload"][0]).read())
    # try:
    start = time.time()
    for i in range(execs):
        if i % 3 == 0:
            q.set_payload(open(config.argument_values["payload"][0]).read())
        # time.sleep(0.01 * randint(0, 9))
        print("+----------------------------------------------+")
        # a = str(q.send_payload())
        # hexdump(a)
        current_hash = q.send_payload().hash()
        if zero_hash == current_hash:
            print("Hash: " + str(
                current_hash) + common.color.WARNING + " (WARNING: Zero hash found!)" + common.color.ENDC)
        else:
            print("Hash: " + str(current_hash))
    end = time.time()
    print("Performance: " + str(execs / (end - start)) + "t/s")
    # except:
    #    print("EXC")

    q.__del__()
    try:
        for i in range(512):
            if os.path.exists("/tmp/kAFL_printf.txt." + str(i)):
                os.remove("/tmp/kAFL_printf.txt." + str(i))
            else:
                break
    except:
        pass
    os.system("stty sane")
    return 0


def debug_non_det(config, payload, max_iterations=0, q=None):
    log_info("Starting...")

    # Define IP Range!!
    if q is None:
        q = qemu(1337, config, debug_mode=False)
        q.start(verbose=False)
    hash_value = None
    default_hash = None
    hash_list = []
    try:
        q.set_payload(payload)
        bitmap = q.send_payload()
        # bitmap = q.send_payload()
        default_hash = bitmap.hash()
        hash_list.append(default_hash)

        # q.set_payload(open(config.argument_values["payload"]).read())
        # bitmap = q.send_payload()
        print("Default Hash: " + str(default_hash))
        total = 1
        hash_mismatch = 0
        count = 0
        while True:
            mismatch_r = 0
            start = time.time()
            # for i in range(execs):
            execs = 0
            while (time.time() - start < REFRESH):
                # time.sleep(0.00001 * randint(0, 9))
                # q.set_payload(open(config.argument_values["payload"]).read())
                q.set_payload(payload)
                bitmap = q.send_payload()

                hash_value = bitmap.hash()
                if hash_value != default_hash:
                    mismatch_r += 1
                    if hash_value not in hash_list:
                        hash_list.append(hash_value)
                    # print(common.color.FAIL + "[WARNING]: hash mismatch" + common.color.ENDC)
                execs += 1
            end = time.time()
            total += execs
            hash_mismatch += mismatch_r
            # print("Performance: " +  str(format(((execs*0.1)/(end - start)), '.4f')) + "  t/s\tTotal: " + str(total) + "\tMismatch: " + common.color.FAIL + str(hash_mismatch) + common.color.ENDC + " (+" + str(mismatch_r) + ")\tRatio: " + str(format(((hash_mismatch*1.0)/total)*100.00, '.4f')) + "%")
            stdout.write(common.color.FLUSH_LINE + "Performance: " + str(
                format(((execs * 1.0) / (end - start)), '.4f')) + "  t/s\tTotal: " + str(total) + "\tMismatch: ")
            if (len(hash_list) != 1):
                stdout.write(common.color.FAIL + str(hash_mismatch) + common.color.ENDC + " (+" + str(
                    mismatch_r) + ")\tRatio: " + str(format(((hash_mismatch * 1.0) / total) * 100.00, '.4f')) + "%")
                stdout.write("\t\tHashes:\t" + str(len(hash_list)) + " (" + str(
                    format(((len(hash_list) * 1.0) / total) * 100.00, '.4f')) + "%)")
            else:
                stdout.write(common.color.OKGREEN + str(hash_mismatch) + common.color.ENDC + " (+" + str(
                    mismatch_r) + ")\tRatio: " + str(format(((hash_mismatch * 1.0) / total) * 100.00, '.4f')) + "%")
            stdout.flush()

            if max_iterations != 0 and total >= count:
                break

            count += 1

    except Exception as e:
        pass
        # if max_iterations == 0:
        # print("\nExit + (" + str(e) + ")")
        # print('Error on line {}'.format(sys.exc_info()[-1].tb_lineno), type(e).__name__, e)

    if max_iterations != 0:
        print("")

    for e in hash_list:
        print(e)

    if max_iterations != 0:
        print("")

    # q.__del__()
    try:
        for i in range(512):
            if os.path.exists("/tmp/kAFL_printf.txt." + str(i)):
                os.remove("/tmp/kAFL_printf.txt." + str(i))
            else:
                break
    except:
        pass
    return 0


thread_done = False
first_line = True


def requeen_print_state(qemu):
    global first_line
    if not first_line:
        stdout.write(common.color.MOVE_CURSOR_UP(1))
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

    stdout.write(common.color.FLUSH_LINE + "Log Size:\t" + size_a + " Bytes\tSE Size:\t" + size_b + " Bytes\n")
    stdout.flush()


def parse_input_cov_list(inputs):
    import csv
    input_to_timestamp = {}

    if len(inputs) == 1 and "list.txt" == os.path.basename(inputs[0]):
        file_name = inputs[0]
        inputs = []
        with open(file_name) as csv_file:
            csv_reader = csv.reader(csv_file, delimiter=';')
            for row in csv_reader:
                file_name = row[0]
                timestamp = None
                if len(row) > 1:
                    timestamp = float(row[1])
                inputs.append(file_name)
                input_to_timestamp[file_name] = timestamp

            inputs.sort(key=lambda x: input_to_timestamp[x])
    return inputs, input_to_timestamp


def plot_bb(inputs, input_to_timestamp, input_to_new_bbs):
    assert all([input_to_timestamp[input_path] is not None for input_path in inputs])

    bb_found = 0

    with open("bb_plot.csv", "wb") as f:
        f.write("{};{}\n".format(0, 0))
        for input_path in inputs:
            if not len(input_to_new_bbs[input_path]):
                continue
            bb_found += len(input_to_new_bbs[input_path])
            f.write("{};{}\n".format(input_to_timestamp[input_path], bb_found))


def redqueen_cov(config, qemu_verbose=False):
    global thread_done
    log_info("Starting...")

    q = qemu(1337, config, debug_mode=True)
    q.start(verbose=qemu_verbose)

    known_lines = set()

    trace_parser = TraceParser(config)

    inputs, input_to_timestamp = parse_input_cov_list(config.argument_values["payload"])

    for input_path in inputs:
        name = os.path.basename(input_path)
        print(common.color.OKGREEN + "Running: %s" % input_path + common.color.ENDC)
        q.set_payload(open(input_path).read())
        start = time.time()
        result = q.execute_in_trace_mode(debug_mode=True, timeout_detection=False)
        end = time.time()
        if result:
            print(common.color.OKGREEN + "Execution succeded!" + common.color.ENDC)
        else:
            print(common.color.FLUSH_LINE + common.color.FAIL + "Execution failed!" + common.color.ENDC)
        print("Time: " + str(end - start) + "t/s")

        trace_parser.parse_and_add_trace(input_path,
                                         "/tmp/kafl_debug_workdir/redqueen_workdir_1337/pt_trace_results.txt")

    input_to_new_bbs = trace_parser.input_to_new_targets

    if all([input_to_timestamp.get(input_path) is not None for input_path in inputs]):
        plot_bb(inputs, input_to_timestamp, input_to_new_bbs)
    else:
        for input in sorted(list(input_to_new_bbs)):
            safe_print("%s: %s" % (input, repr(map(hex, input_to_new_bbs[input]))))

    count = 0
    for _, bbs in input_to_new_bbs.items():
        count += len(bbs)
    print("total: %d" % count)

    print("kill qemu")
    os.system("killall -9 qemu-system-x86_64")
    q.__del__()

    print("fix tty")
    os.system("stty sane")
    print("kill python")
    os.system("killall -9 python")
    return 0


def redqueen_dbg_thread(q):
    global thread_done, first_line
    while not thread_done:
        time.sleep(0.5)
        if not thread_done:
            requeen_print_state(q)


def redqueen_dbg(config, qemu_verbose=False):
    global thread_done
    log_info("Starting...")

    q = qemu(1337, config, debug_mode=True)
    q.start(verbose=qemu_verbose)
    payload = open(config.argument_values["payload"][0]).read()
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
        print(common.color.OKGREEN + "Execution succeded!" + common.color.ENDC)
    else:
        print(common.color.FLUSH_LINE + common.color.FAIL + "Execution failed!" + common.color.ENDC)
    print("Time: " + str(end - start) + "t/s")

    num_muts, muts = parser.parse_rq_data(
        open("/tmp/kafl_debug_workdir/redqueen_workdir_1337/redqueen_results.txt").read(), payload)
    count = 0
    for offset in muts:
        for lhs in muts[offset]:
            for rhs in muts[offset][lhs]:
                count += 1
                print(offset, lhs, rhs)
    print(count)

    q.__del__()
    os.system("stty sane")
    return 0


def verify_dbg(config, qemu_verbose=False):
    global thread_done

    log_info("Starting...")

    rq_state = RedqueenState()
    workdir = RedqueenWorkdir(1337)

    if os.path.exists("patches"):
        with open("patches", "r") as f:
            for x in f.readlines():
                rq_state.add_candidate_hash_addr(int(x, 16))
    if not rq_state.get_candidate_hash_addrs():
        print
        "WARNING: no patches configured\n"
        print
        "Maybe add ./patches with addresses to patch\n"
    else:
        print
        "OK: got patches %s\n" % rq_state.get_candidate_hash_addrs()
    q = qemu(1337, config, debug_mode=True)

    print("using qemu command:\n%s\n" % q.cmd)

    q.start(verbose=qemu_verbose)

    orig_input = open(config.argument_values["payload"][0]).read()
    q.set_payload(orig_input)

    # result = q.send_payload()

    with open(q.redqueen_workdir.whitelist(), "w") as w:
        with open(q.redqueen_workdir.patches(), "w") as p:
            for addr in rq_state.get_candidate_hash_addrs():
                addr = hex(addr).rstrip("L").lstrip("0x") + "\n"
                w.write(addr)
                p.write(addr)

    print("RUN WITH PATCHING:")
    bmp1 = q.send_payload(apply_patches=True)

    print("\nNOT PATCHING:")
    bmp2 = q.send_payload(apply_patches=False)

    if bmp1 == bmp2:
        print
        "WARNING: patches don't seem to change anything, are checksums present?"
    else:
        print
        "OK: bitmaps are distinct"

    q.soft_reload()

    hash = HashFixer(q, rq_state)

    print
    "fixing hashes\n"
    fixed_payload = hash.try_fix_data(orig_input)
    if fixed_payload:

        print
        repr("".join(map(chr, fixed_payload)))

        q.set_payload(fixed_payload)

        bmp3 = q.send_payload(apply_patches=False)

        if bmp1 == bmp3:
            print
            "CONGRATZ, BITMAPS ARE THE SAME, all cmps fixed\n"
        else:
            print
            "Warning, after fixing cmps, bitmaps differ\n"
    else:
        print
        "couldn't fix payload"

    start = time.time()
    q.__del__()
    os.system("stty sane")
    return 0


def start():
    config = DebugConfiguration()

    prepare_working_dir(config.argument_values['work_dir'])

    if not post_self_check(config):
        return -1

    if config.argument_values['v']:
        enable_logging(config.argument_values["work_dir"])

    if not config.argument_values['ip0']:
        print(common.color.WARNING + "[WARNING]\tNo trace region configured!" + common.color.ENDC)

    if (config.argument_values['debug_mode'] == "noise"):
        debug_non_det(config, open(config.argument_values["payload"][0]).read())
    if (config.argument_values['debug_mode'] == "noise-multiple"):
        q = qemu(1337, config, debug_mode=False)
        q.start(verbose=False)
        for e in config.argument_values["payload"]:
            print("FILE: " + e)
            debug_non_det(config, open(e).read(), max_iterations=20, q=q)
    elif (config.argument_values['debug_mode'] == "benchmark"):
        benchmark(config)
    elif (config.argument_values['debug_mode'] == "trace"):
        debug_execution(config, config.argument_values['i'])
    elif (config.argument_values['debug_mode'] == "trace-qemu"):
        debug_execution(config, config.argument_values['i'], qemu_verbose=True)
    elif (config.argument_values['debug_mode'] == "printk"):
        debug_execution(config, 1, qemu_verbose=True, notifiers=False)
    elif (config.argument_values['debug_mode'] == "redqueen"):
        redqueen_dbg(config, qemu_verbose=False)
    elif (config.argument_values['debug_mode'] == "redqueen-qemu"):
        redqueen_dbg(config, qemu_verbose=True)
    elif (config.argument_values['debug_mode'] == "cov"):
        redqueen_cov(config, qemu_verbose=True)
    elif (config.argument_values['debug_mode'] == "verify"):
        verify_dbg(config, qemu_verbose=True)
    return 0
