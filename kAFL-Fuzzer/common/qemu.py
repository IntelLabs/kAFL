# Copyright 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Launch Qemu VMs and execute test inputs produced by kAFL-Fuzzer.
"""

import ctypes
import mmap
import os
import resource
import select
import socket
import struct
import subprocess
import time
import traceback
from socket import error as socket_error
import sys

import common.color
import common.qemu_protocol as qemu_protocol
from common.debug import log_qemu
from common.execution_result import ExecutionResult
from fuzzer.technique.redqueen.workdir import RedqueenWorkdir
from common.util import read_binary_file, atomic_write, print_fail, strdump


def to_string_32(value):
    return [(value >> 24) & 0xff,
            (value >> 16) & 0xff,
            (value >> 8) & 0xff,
            value & 0xff]


class qemu:
    CMDS = qemu_protocol.CMDS

    def __init__(self, qid, config, debug_mode=False, notifiers=True):

        self.hprintf_print_mode = True
        self.internal_buffer_overflow_counter = 0

        # True => handshake *not yet done*
        self.handshake_stage_1 = True
        self.handshake_stage_2 = True

        self.debug_mode = debug_mode
        self.patches_enabled = False
        self.needs_execution_for_patches = False
        self.debug_counter = 0

        self.agent_size = config.config_values['AGENT_MAX_SIZE']
        self.bitmap_size = config.config_values['BITMAP_SHM_SIZE']
        self.payload_size = config.config_values['PAYLOAD_SHM_SIZE']
        self.config = config
        self.qemu_id = str(qid)

        self.process = None
        self.control = None
        self.persistent_runs = 0

        project_name = self.config.argument_values['work_dir'].split("/")[-1]
        self.payload_filename = "/dev/shm/kafl_%s_qemu_payload_%s" % (project_name, self.qemu_id)
        self.tracedump_filename = "/dev/shm/kafl_%s_pt_trace_dump_%s" % (project_name, self.qemu_id)
        self.binary_filename = self.config.argument_values['work_dir'] + "/program"
        self.bitmap_filename = "/dev/shm/kafl_%s_bitmap_%s" % (project_name, self.qemu_id)

        self.control_filename = self.config.argument_values['work_dir'] + "/interface_" + self.qemu_id
        self.qemu_trace_log = self.config.argument_values['work_dir'] + "/qemu_trace_%s.log" % self.qemu_id
        self.qemu_serial_log = self.config.argument_values['work_dir'] + "/qemu_serial_%s.log" % self.qemu_id

        self.redqueen_workdir = RedqueenWorkdir(self.qemu_id, config)
        self.redqueen_workdir.init_dir()

        self.exiting = False
        self.tick_timeout_treshold = self.config.config_values["TIMEOUT_TICK_FACTOR"]

        self.cmd = self.config.config_values['QEMU_KAFL_LOCATION']

        self.catch_vm_reboots = self.config.argument_values['catch_resets']

        # TODO: list append should work better than string concatenation, especially for str.replace() and later popen()
        self.cmd += " -serial file:" + self.qemu_serial_log + \
                    " -enable-kvm" \
                    " -m " + str(config.argument_values['mem']) + \
                    " -nographic -net none" \
                    " -chardev socket,server,nowait,path=" + self.control_filename + \
                    ",id=kafl_interface" \
                    " -device kafl,chardev=kafl_interface,bitmap_size=" + str(self.bitmap_size) + ",shm0=" + self.binary_filename + \
                    ",shm1=" + self.payload_filename + \
                    ",bitmap=" + self.bitmap_filename + \
                    ",redqueen_workdir=" + self.redqueen_workdir.base_path

        if False:  # do not emit tracefiles on every execution
            self.cmd += ",dump_pt_trace"

        if self.debug_mode:
            self.cmd += ",debug_mode"

        if not notifiers:
            self.cmd += ",crash_notifier=False"

        # fast reload is not part of redqueen release
        # if not self.config.argument_values.has_key('R') or not self.config.argument_values['R']:
        self.cmd += ",reload_mode=False"

        # qemu snapshots only work in VM mode (disk+ram image)
        if self.config.argument_values['kernel'] or self.config.argument_values['bios']:
            self.cmd += ",disable_snapshot=True"

        for i in range(1):
            key = "ip" + str(i)
            if key in self.config.argument_values and self.config.argument_values[key]:
                range_a = hex(self.config.argument_values[key][0]).replace("L", "")
                range_b = hex(self.config.argument_values[key][1]).replace("L", "")
                self.cmd += ",ip" + str(i) + "_a=" + range_a + ",ip" + str(i) + "_b=" + range_b
                #self.cmd += ",filter" + str(i) + "=/dev/shm/kafl_filter" + str(i)

        if self.debug_mode:
            self.cmd += " -d kafl -D " + self.qemu_trace_log

        if self.catch_vm_reboots:
            self.cmd += " -no-reboot"

        if self.config.argument_values['gdbserver']:
            self.cmd += " -s -S"

        if self.config.argument_values['extra']:
            self.cmd += " " + self.config.argument_values['extra']

        # Lauch either as VM snapshot, direct kernel/initrd boot, or -bios boot
        if self.config.argument_values['vm_dir']:
            assert(self.config.argument_values['vm_ram'])
            self.cmd += " -hdb " + self.config.argument_values['vm_ram']
            self.cmd += " -hda " + self.config.argument_values['vm_dir'] + "/overlay_" + self.qemu_id + ".qcow2"
            self.cmd += " -loadvm " + self.config.argument_values["S"]
        elif self.config.argument_values['kernel']:
            self.cmd += " -kernel " + self.config.argument_values['kernel']
            if self.config.argument_values['initrd']:
                self.cmd += " -initrd " + self.config.argument_values['initrd'] + " -append BOOTPARAM "
        elif self.config.argument_values['bios']:
            self.cmd += " -bios " + self.config.argument_values['bios']
        else:
            assert(False), "Must supply either -bios or -kernel or -vm_overlay/-vm_ram option"

        if self.config.argument_values["macOS"]:
            self.cmd = self.cmd.replace("-nographic -net none",
                    "-nographic -netdev user,id=hub0port0 -device e1000-82545em,netdev=hub0port0,id=mac_vnet0 -cpu Penryn,kvm=off,vendor=GenuineIntel -device isa-applesmc,osk=\"" + self.config.config_values["APPLE-SMC-OSK"].replace("\"", "") + "\" -machine pc-q35-2.4")
            if self.qemu_id == 0:
                self.cmd = self.cmd.replace("-machine pc-q35-2.4", "-machine pc-q35-2.4 -redir tcp:5901:0.0.0.0:5900 -redir tcp:10022:0.0.0.0:22")
        else:
            self.cmd += " -machine q35 "


        self.crashed = False
        self.timeout = False
        self.kasan = False

        self.virgin_bitmap = bytes(self.bitmap_size)

        # split cmd into list of arguments for Popen(), replace BOOTPARAM as single element
        self.cmd = [_f for _f in self.cmd.split(" ") if _f]
        c = 0
        for i in self.cmd:
            if i == "BOOTPARAM":
                self.cmd[c] = "\"nokaslr oops=panic nopti mitigations=off\""
                break
            c += 1

    def __debug_hprintf(self):
        try:
            if self.debug_counter < 512:
                data = ""
                for line in open("/tmp/kAFL_printf.txt." + str(self.debug_counter)):
                    data += line
                self.debug_counter += 1
                if data.endswith('\n'):
                    data = data[:-1]
                if self.hprintf_print_mode:
                    print("[HPRINTF]\t" + '\033[0;33m' + data + '\033[0m')
                else:
                    print('\033[0;33m' + data + '\033[0m')
        except Exception as e:
            print("__debug_hprintf: " + str(e))

    def send_enable_redqueen(self):
        self.__debug_send(qemu_protocol.ENABLE_RQI_MODE)
        self.__debug_recv_expect(qemu_protocol.ENABLE_RQI_MODE)

    def send_disable_redqueen(self):
        self.__debug_send(qemu_protocol.DISABLE_RQI_MODE)
        self.__debug_recv_expect(qemu_protocol.DISABLE_RQI_MODE)

    def send_enable_patches(self):
        if not self.patches_enabled:
            assert (not self.needs_execution_for_patches)
            self.needs_execution_for_patches = True
            self.patches_enabled = True
            self.__debug_send(qemu_protocol.ENABLE_PATCHES)
            self.__debug_recv_expect(qemu_protocol.ENABLE_PATCHES)

    def send_disable_patches(self):
        if self.patches_enabled:
            assert (not self.needs_execution_for_patches)
            self.needs_execution_for_patches = True
            self.patches_enabled = False
            self.__debug_send(qemu_protocol.DISABLE_PATCHES)
            self.__debug_recv_expect(qemu_protocol.DISABLE_PATCHES)
        pass

    def send_enable_trace(self):
        self.__debug_send(qemu_protocol.ENABLE_TRACE_MODE)
        self.__debug_recv_expect(qemu_protocol.ENABLE_TRACE_MODE)

    def send_disable_trace(self):
        self.__debug_send(qemu_protocol.DISABLE_TRACE_MODE)
        self.__debug_recv_expect(qemu_protocol.DISABLE_TRACE_MODE)

    def send_rq_set_light_instrumentation(self):
        self.__debug_send(qemu_protocol.REDQUEEN_SET_LIGHT_INSTRUMENTATION)
        self.__debug_recv_expect(qemu_protocol.REDQUEEN_SET_LIGHT_INSTRUMENTATION)

    def send_rq_set_whitelist_instrumentation(self):
        self.__debug_send(qemu_protocol.REDQUEEN_SET_WHITELIST_INSTRUMENTATION)
        self.__debug_recv_expect(qemu_protocol.REDQUEEN_SET_WHITELIST_INSTRUMENTATION)

    def send_rq_update_blacklist(self):
        self.__debug_send(qemu_protocol.REDQUEEN_SET_BLACKLIST)
        self.__debug_recv_expect(qemu_protocol.REDQUEEN_SET_BLACKLIST)

    def __debug_send(self, cmd):
        #self.last_bitmap_wrapper.invalidate() # works on a copy, probably obsolete..
        if self.debug_mode:
                info = ""
                if self.handshake_stage_1 and cmd == qemu_protocol.RELEASE:
                    info = " (Agent Init)"
                    self.handshake_stage_1 = False
                elif self.handshake_stage_2 and cmd == qemu_protocol.RELEASE:
                    info = " (Agent Run)"
                    self.handshake_stage_2 = False
                try:
                    log_qemu("[SEND] " + '\033[94m' + self.CMDS[cmd] + info + '\033[0m', self.qemu_id)
                except:
                    log_qemu("[SEND] " + "unknown cmd '" + res + "'", self.qemu_id)
        try:
            self.control.send(cmd)
        except (BrokenPipeError, OSError):
            if not self.exiting:
                log_qemu("Fatal error in __debug_send()", self.qemu_id)
                self.shutdown()
                raise

    def __dump_recv_res(self, res):
        if res == qemu_protocol.ACQUIRE:
            self.debug_counter = 0
        # try:
        info = ""
        if self.handshake_stage_1 and res == qemu_protocol.RELEASE:
            info = " (Agent Init)"
        elif self.handshake_stage_2 and res == qemu_protocol.ACQUIRE:
            info = " (Agent Ready)"
        elif res == qemu_protocol.INFO:
            log_qemu("[RECV] " + '\033[1m' + '\033[92m' + self.CMDS[res] + info + '\033[0m', self.qemu_id)
            log_qemu("------------------------------------------------------", self.qemu_id)
            try:
                for line in open("/tmp/kAFL_info.txt"):
                    log_qemu(line, self.qemu_id)
                os.remove("/tmp/kAFL_info.txt")
            except:
                pass
            log_qemu("------------------------------------------------------", self.qemu_id)
            os._exit(0)
        elif res == qemu_protocol.ABORT:
            #print(common.color.FAIL + self.CMDS[res] + common.color.ENDC)
            log_qemu("[RECV] " + common.color.FAIL + self.CMDS[res] + common.color.ENDC, self.qemu_id)
            os._exit(0)
        if res == qemu_protocol.CRASH or res == qemu_protocol.KASAN:
            log_qemu("[RECV] " + '\033[1m' + '\033[91m' + self.CMDS[res] + info + '\033[0m', self.qemu_id)
        else:
            try:
                log_qemu("[RECV] " + '\033[1m' + '\033[92m' + self.CMDS[res] + info + '\033[0m', self.qemu_id)
            except Exception as e:
                log_qemu("[RECV] " + "unknown cmd '" + res + "'" + str(e), self.qemu_id)
                raise e

    def __debug_recv(self):
        while True:
            try:
                res = self.control.recv(1)
            except ConnectionResetError:
                if self.exiting:
                    sys.exit(0)
                raise

            if (len(res) == 0):
                # Another case of socket error, apparently on Qemu reset/crash
                if self.catch_vm_reboots:
                    # Treat event as Qemu reset triggered by target, and log as KASAN
                    log_qemu("Qemu exit? - Assuming target crash/reset (KASAN)", self.qemu_id)
                    return qemu_protocol.KASAN
                else:
                    # Default: assume Qemu exit is fatal bug in harness/setup
                    log_qemu("Fatal error in __debug_recv()", self.qemu_id)
                    sig = self.shutdown()
                    if sig == 0: # regular shutdown? still report as KASAN
                        return qemu_protocol.KASAN
                    else:
                        raise BrokenPipeError("Qemu exited with signal: %s" % str(sig))

            if res == qemu_protocol.PRINTF:
                self.__debug_hprintf()
                self.hprintf_print_mode = False
            else:
                self.hprintf_print_mode = True

                if self.debug_mode:
                    try:
                        self.__dump_recv_res(res)
                    except:
                        pass

                return res

    def __debug_recv_expect(self, cmd):
        res = ''
        while True:

            res = self.__debug_recv()
            if res in cmd:
                break
            # TODO: the I/O handling here really sucks.
            # Below we are returning OK to set_init_state() in order to silence handshake error message during kafl_info.py.
            # We need to factor out the debug stuff and properly support required vs optional/intermediate control messages...
            elif res == qemu_protocol.INFO:
                break
            elif res is None:
                # Timeout is detected separately in debug_recv(), so we should never get here..
                assert False
            else:
                # Reaching this part typically means there is a bug in the agent or target setup which
                # messes up the expected interaction. Throw an error and exit.
                log_qemu("Fatal error in debug_recv(): Got " + str(res) + ", Expected: " + str(cmd) + ")", self.qemu_id)
                print_fail("Slave %s: Error in debug_recv(): Got %s, Expected: %s" % (self.qemu_id, str(res), str(cmd)))
                self.async_exit()
        if res == qemu_protocol.PT_TRASHED:
            log_qemu("PT_TRASHED", self.qemu_id)
            return False
        return True

    # Asynchronous exit by slave instance. Note this may be called multiple times
    # while we were in the middle of shutdown(), start(), send_payload(), ..
    def async_exit(self):
        if self.exiting:
            sys.exit(0)

        self.exiting = True
        self.shutdown()

        for tmp_file in [
                self.payload_filename,
                self.tracedump_filename,
                self.control_filename,
                self.binary_filename,
                self.bitmap_filename]:
            try:
                os.remove(tmp_file)
            except:
                pass


    def shutdown(self):
        log_qemu("Shutting down Qemu after %d execs.." % self.persistent_runs, self.qemu_id)
        
        if not self.process:
            # start() has never been called, all files/shm are closed.
            return 0

        # If Qemu exists, try to graciously read its I/O and SIGTERM it.
        # If still alive, attempt SIGKILL or loop-wait on kill -9.
        output = "<no output received>\n"
        try:
            self.process.terminate()
            output = strdump(self.process.communicate(timeout=1)[0], verbatim=True)
        except:
            pass

        if self.process.returncode is None:
            try:
                self.process.kill()
            except:
                pass

        log_qemu("Qemu exit code: %s" % str(self.process.returncode), self.qemu_id)
        header = "\n=================<Qemu %s Console Output>==================\n" % self.qemu_id
        footer = "====================</Console Output>======================\n"
        log_qemu(header + output + footer, self.qemu_id)

        if os.path.isfile(self.qemu_serial_log):
            header = "\n=================<Qemu %s Serial Output>==================\n" % self.qemu_id
            footer = "====================</Serial Output>======================\n"
            serial_out = strdump(read_binary_file(self.qemu_serial_log), verbatim=True)
            log_qemu(header + serial_out + footer, self.qemu_id)


        try:
            # TODO: exec_res keeps from_buffer() reference to kafl_shm
            self.kafl_shm.close()
        except BufferError as e:
            pass

        try:
            self.fs_shm.close()
        except:
            pass

        try:
            os.close(self.kafl_shm_f)
        except:
            pass

        try:
            os.close(self.fs_shm_f)
        except:
            pass

        return self.process.returncode

    def __set_agent(self):
        agent_bin = self.config.argument_values['agent']
        bin = read_binary_file(agent_bin)
        assert (len(bin) <= self.agent_size)
        atomic_write(self.binary_filename, bin)

    def start(self):

        if self.exiting:
            return False

        self.persistent_runs = 0
        self.handshake_stage_1 = True
        self.handshake_stage_2 = True

        if self.qemu_id == "0" or self.qemu_id == "1337": ## 1337 is debug instance!
            log_qemu("Launching virtual machine...CMD:\n" + ' '.join(self.cmd), self.qemu_id)
        else:
            log_qemu("Launching virtual machine...", self.qemu_id)


        # Launch Qemu. stderr to stdout, stdout is logged on VM exit
        # os.setpgrp() prevents signals from being propagated to Qemu, instead allowing an
        # organized shutdown via async_exit()
        self.process = subprocess.Popen(self.cmd,
                preexec_fn=os.setpgrp,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT)

        try:
            self.__qemu_connect()
            self.__qemu_handshake()
        except (OSError, BrokenPipeError) as e:
            if not self.exiting:
                print_fail("Failed to launch Qemu, please see logs. Error: " + str(e))
                log_qemu("Fatal error: Failed to launch Qemu: " + str(e), self.qemu_id)
                self.shutdown()
            return False

        return True

    def __qemu_handshake(self):

        if self.config.argument_values['agent']:
            self.__set_agent()

        self.__debug_recv_expect(qemu_protocol.RELEASE + qemu_protocol.PT_TRASHED)
        self.__debug_send(qemu_protocol.RELEASE)
        log_qemu("Stage 1 handshake done [INIT]", self.qemu_id)

        # TODO: notify user if target/VM loads really slow or not at all..
        #ready = select.select([self.control], [], [], 0.5)
        #while not ready[0]:
        #    print("[Slave %d] Waiting for Qemu handshake..." % self.qemu_id)
        #    ready = select.select([self.control], [], [], 1)

        self.handshake_stage_1 = False
        self.__debug_recv_expect(qemu_protocol.ACQUIRE + qemu_protocol.PT_TRASHED)
        log_qemu("Stage 2 handshake done [READY]", self.qemu_id)
        self.handshake_stage_2 = False

    def __qemu_connect(self):
        # Note: setblocking() disables the timeout! settimeout() will automatically set blocking!
        self.control = socket.socket(socket.AF_UNIX)
        self.control.settimeout(None)
        self.control.setblocking(1)

        # TODO: Don't try forever, set some timeout..
        while True:
            try:
                self.control.connect(self.control_filename)
                break
            except socket_error:
                if self.process.returncode is not None:
                    raise

        self.kafl_shm_f     = os.open(self.bitmap_filename, os.O_RDWR | os.O_SYNC | os.O_CREAT)
        self.fs_shm_f       = os.open(self.payload_filename, os.O_RDWR | os.O_SYNC | os.O_CREAT)

        open(self.tracedump_filename, "wb").close()

        with open(self.binary_filename, 'bw') as f:
            os.ftruncate(f.fileno(), self.agent_size)

        os.ftruncate(self.kafl_shm_f, self.bitmap_size)
        os.ftruncate(self.fs_shm_f, self.payload_size)

        self.kafl_shm = mmap.mmap(self.kafl_shm_f, 0)
        self.c_bitmap = (ctypes.c_uint8 * self.bitmap_size).from_buffer(self.kafl_shm)
        self.fs_shm = mmap.mmap(self.fs_shm_f, 0)

        return True

    # Fully stop/start Qemu instance to store logs + possibly recover
    def restart(self):

        self.shutdown()
        # TODO: Need to wait here or else the next instance dies in set_payload()
        # Perhaps Qemu should do proper munmap()/close() on exit?
        time.sleep(0.1)
        return self.start()

    # Reset Qemu after crash/timeout - can skip if target has own forkserver
    def reload(self):
        if self.config.argument_values['forkserver']:
            return True
        else:
            return self.restart()

    # Reload is not part of released Redqueen backend, it seems we can simply disable it here..
    def soft_reload(self):
        return

        log_qemu("soft_reload()", self.qemu_id)
        self.crashed = False
        self.timeout = False
        self.kasan = False

        self.__debug_send(qemu_protocol.RELOAD)
        self.__debug_recv_expect(qemu_protocol.RELOAD)
        success = self.__debug_recv_expect(qemu_protocol.ACQUIRE + qemu_protocol.PT_TRASHED)

        if not success:
            log_qemu("soft reload failed (ipt ovp quirk)", self.qemu_id)
            self.soft_reload()

    # TODO: can directly return result for handling by caller?
    # TODO: document protocol and meaning/effect of each message
    def check_recv(self, timeout_detection=True):
        if timeout_detection:
            ready = select.select([self.control], [], [], 0.25)
            if not ready[0]:
                return 2
        else:
            ready = select.select([self.control], [], [], 5.0)
            if not ready[0]:
                return 2

        result = self.__debug_recv()

        if result == qemu_protocol.CRASH:
            return 1
        elif result == qemu_protocol.KASAN:
            return 3
        elif result == qemu_protocol.TIMEOUT:
            return 7
        elif result == qemu_protocol.ACQUIRE:
            return 0
        elif result == qemu_protocol.PT_TRASHED:
            self.internal_buffer_overflow_counter += 1
            return 4
        elif result == qemu_protocol.PT_TRASHED_CRASH:
            self.internal_buffer_overflow_counter += 1
            return 5
        elif result == qemu_protocol.PT_TRASHED_KASAN:
            self.internal_buffer_overflow_counter += 1
            return 6
        else:
            # TODO: detect+log errors without affecting fuzz campaigns
            #raise ValueError("Unhandled Qemu message %s" % repr(result))
            return 0

    # Wait forever on Qemu to execute the payload - useful for interactive debug
    def debug_payload(self, apply_patches=True):

        # TODO: do we care about this?
        if apply_patches:
            self.send_enable_patches()
        else:
            self.send_disable_patches()

        self.__debug_send(qemu_protocol.RELEASE)

        while True:
            ready = select.select([self.control], [], [], 0.5)
            if ready[0]:
                break

        result = self.__debug_recv()
        return result

    def send_payload(self, apply_patches=True, timeout_detection=True, max_iterations=10):

        if (self.debug_mode):
            log_qemu("Send payload..", self.qemu_id)

        if self.exiting:
            sys.exit(0)

        self.persistent_runs += 1
        start_time = time.time()
        # TODO: added in redqueen - verify what this is doing
        if apply_patches:
            self.send_enable_patches()
        else:
            self.send_disable_patches()
        self.__debug_send(qemu_protocol.RELEASE)

        self.crashed = False
        self.timeout = False
        self.kasan = False

        repeat = False
        value = self.check_recv(timeout_detection=timeout_detection)
        if value == 0:
            pass # all good
        elif value == 1:
            log_qemu("Crash detected!", self.qemu_id)
            self.crashed = True
        elif value == 2:
            log_qemu("Timeout detected!", self.qemu_id)
            self.timeout = True
        elif value == 3:
            log_qemu("Kasan detected!", self.qemu_id)
            self.kasan = True
        elif value == 4:
            repeat = True
        elif value == 5:
            repeat = True
            self.soft_reload()
        elif value == 6:
            repeat = True
            self.soft_reload()
        elif value == 7:
            log_qemu("Timeout detected!", self.qemu_id)
            self.timeout = True
        else:
            # TODO: detect+log errors without affecting fuzz campaigns
            #raise ValueError("Unhandled return code %s" % str(value))
            pass

        self.needs_execution_for_patches = False

        ## repeat logic - enable starting with RQ release..
        if repeat:
            log_qemu("Repeating iteration...", self.qemu_id)
            if max_iterations != 0:
                self.send_payload(apply_patches=apply_patches, timeout_detection=timeout_detection, max_iterations=0)
                res = self.send_payload(apply_patches=apply_patches, timeout_detection=timeout_detection,
                                        max_iterations=max_iterations - 1)
                res.performance = time.time() - start_time
                return res

        return ExecutionResult(self.c_bitmap, self.bitmap_size, self.exit_reason(), time.time() - start_time)

    def exit_reason(self):
        if self.crashed:
            return "crash"
        elif self.timeout:
            return "timeout"
        elif self.kasan:
            return "kasan"
        else:
            return "regular"

    def enable_sampling_mode(self):
        self.__debug_send(qemu_protocol.ENABLE_SAMPLING)

    def disable_sampling_mode(self):
        self.__debug_send(qemu_protocol.DISABLE_SAMPLING)

    def submit_sampling_run(self):
        self.__debug_send(qemu_protocol.COMMIT_FILTER)

    def execute_in_trace_mode(self, timeout_detection):
        log_qemu("Performing trace iteration...", self.qemu_id)
        exec_res = None
        try:
            self.soft_reload()
            self.send_enable_trace()
            exec_res = self.send_payload(timeout_detection=timeout_detection)
            self.soft_reload()
            self.send_disable_trace()
        except Exception as e:
            log_qemu("Error during trace: %s" % str(e), self.qemu_id)
            return None

        return exec_res

    def execute_in_redqueen_mode(self, payload):
        log_qemu("Performing redqueen iteration...", self.qemu_id)
        try:
            self.soft_reload()
            self.send_rq_set_light_instrumentation()
            self.send_enable_redqueen()
            self.set_payload(payload)
            self.send_payload(timeout_detection=False)
            if self.exit_reason() != "regular":
                print_warning("RQ execution returned %s", self.exit_reason())
        except Exception as e:
            log_qemu("%s" % traceback.format_exc(), self.qemu_id)
            return False

        #log_qemu("Disabling redqueen mode...", self.qemu_id)
        try:
            self.send_disable_redqueen()
            self.set_payload(payload)
            self.send_payload(timeout_detection=False)
            self.soft_reload()
            if self.exit_reason() != "regular":
                print_warning("RQ execution returned %s", self.exit_reason())
        except Exception as e:
            log_qemu("%s" % traceback.format_exc(), self.qemu_id)
            return False
        return True

    def set_payload(self, payload):
        if self.exiting:
            sys.exit(0)

        # actual payload is limited to payload_size - sizeof(uint32) - sizeof(uint8)
        if len(payload) > self.payload_size-5:
            payload = payload[:self.payload_size-5]
        try:
            self.fs_shm.seek(0)
            input_len = to_string_32(len(payload))
            self.fs_shm.write_byte(input_len[3])
            self.fs_shm.write_byte(input_len[2])
            self.fs_shm.write_byte(input_len[1])
            self.fs_shm.write_byte(input_len[0])
            self.fs_shm.write(payload)
            self.fs_shm.flush()
        except ValueError:
            if self.exiting:
                sys.exit(0)
            # Qemu crashed. Could be due to prior payload but more likely harness/config is broken..
            #print_fail("Failed to set new payload - Qemu crash?");
            log_qemu("Failed to set new payload - Qemu crash?", self.qemu_id);
            raise
