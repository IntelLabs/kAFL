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

import common.color
import common.qemu_protocol as qemu_protocol
from common.debug import log_qemu
from common.execution_result import ExecutionResult
from common.safe_syscall import safe_print
from common.safe_syscall import safe_select, safe_socket
from fuzzer.technique.redqueen.workdir import RedqueenWorkdir
from common.util import read_binary_file, atomic_write


def to_string_32(value):
    return chr((value >> 24) & 0xff) + \
           chr((value >> 16) & 0xff) + \
           chr((value >> 8) & 0xff) + \
           chr(value & 0xff)


class qemu:
    SC_CLK_TCK = os.sysconf(os.sysconf_names['SC_CLK_TCK'])

    CMDS = qemu_protocol.CMDS

    def __init__(self, qid, config, debug_mode=False, notifiers=True):

        self.bb_count = 0
        self.hprintf_print_mode = True
        self.internal_buffer_overflow_counter = 0

        self.handshake_stage_1 = True
        self.handshake_stage_2 = True

        self.debug_mode = debug_mode
        self.patches_enabled = False
        self.needs_execution_for_patches = False
        self.debug_counter = 0

        self.bitmap_size = config.config_values['BITMAP_SHM_SIZE']
        self.config = config
        self.qemu_id = str(qid)

        self.process = None
        self.intervm_tty_write = None
        self.control = None
        self.control_fileno = None

        project_name = self.config.argument_values['work_dir'].split("/")[-1]
        self.payload_filename = "/dev/shm/kafl_%s_qemu_payload_%s" % (project_name, self.qemu_id)
        self.tracedump_filename = "/dev/shm/kafl_%s_pt_trace_dump_%s" % (project_name, self.qemu_id)
        self.binary_filename = self.config.argument_values['work_dir'] + "/program"
        self.bitmap_filename = "/dev/shm/kafl_%s_bitmap_%s" % (project_name, self.qemu_id)

        self.control_filename = self.config.argument_values['work_dir'] + "/interface_" + self.qemu_id

        self.redqueen_workdir = RedqueenWorkdir(self.qemu_id, config)
        self.redqueen_workdir.init_dir()

        self.start_ticks = 0
        self.end_ticks = 0
        self.tick_timeout_treshold = self.config.config_values["TIMEOUT_TICK_FACTOR"]

        self.cmd = self.config.config_values['QEMU_KAFL_LOCATION'] + " "

        if self.config.argument_values.has_key("ram_file"):
            self.cmd += "-hdb " + self.config.argument_values['ram_file'] + " " \
                                                                            "-hda " + self.config.argument_values[
                            'overlay_dir'] + "/overlay_" + self.qemu_id + ".qcow2 "

        if self.config.argument_values.has_key("kernel"):
            self.cmd += "-kernel " + self.config.argument_values['kernel'] + " " \
                                                                             "-initrd " + self.config.argument_values[
                            'initramfs'] + " -append BOOTPARAM "

        self.cmd += "-serial mon:stdio " \
                    "-enable-kvm " \
                    "-k de " \
                    "-m " + str(config.argument_values['mem']) + " " \
                                                                 "-nographic " \
                                                                 "-net user " \
                                                                 "-net nic " \
                                                                 "-chardev socket,server,nowait,path=" + self.control_filename + \
                    ",id=kafl_interface " \
                    "-device kafl,chardev=kafl_interface,bitmap_size=" + str(
            self.bitmap_size) + ",worker_id=%s" % self.qemu_id + \
                    ",workdir=" + self.config.argument_values['work_dir']
        if False:  # do not emit tracefiles on every execution
            self.cmd += ",dump_pt_trace"
        if debug_mode:
            self.cmd += ",debug_mode"

        if not notifiers:
            self.cmd += ",crash_notifier=False"

        if not self.config.argument_values.has_key('R') or not self.config.argument_values['R']:
            self.cmd += ",reload_mode=False"

        if self.config.argument_values.has_key("kernel"):
            self.cmd += ",disable_snapshot=True"

        for i in range(1):
            key = "ip" + str(i)
            if self.config.argument_values.has_key(key) and self.config.argument_values[key]:
                range_a = hex(self.config.argument_values[key][0]).replace("L", "")
                range_b = hex(self.config.argument_values[key][1]).replace("L", "")
                self.cmd += ",ip" + str(i) + "_a=" + range_a + ",ip" + str(i) + "_b=" + range_b

        if self.config.argument_values.has_key("ram_file"):
            self.cmd += " -loadvm " + self.config.argument_values["S"] + " "

        if self.config.argument_values["macOS"]:
            self.cmd = self.cmd.replace("-net user -net nic",
                                        "-netdev user,id=hub0port0 -device e1000-82545em,netdev=hub0port0,id=mac_vnet0 -cpu Penryn,kvm=off,vendor=GenuineIntel -device isa-applesmc,osk=\"" +
                                        self.config.config_values["APPLE-SMC-OSK"].replace("\"",
                                                                                           "") + "\" -machine pc-q35-2.4")
            if qid == 0:
                self.cmd = self.cmd.replace("-machine pc-q35-2.4",
                                            "-machine pc-q35-2.4 -redir tcp:5901:0.0.0.0:5900 -redir tcp:10022:0.0.0.0:22")
        else:
            self.cmd += " -machine pc-i440fx-2.6 "

        self.kafl_shm_f = None
        self.kafl_shm = None
        self.fs_shm_f = None
        self.fs_shm = None

        self.payload_shm_f = None
        self.payload_shm = None

        self.bitmap_shm_f = None
        self.bitmap_shm = None

        self.e = select.epoll()
        self.crashed = False
        self.timeout = False
        self.kasan = False
        self.shm_problem = False
        self.initial_mem_usage = 0

        self.stat_fd = None

        if qid == 0 or qid == 1337:
            log_qemu("Launching Virtual Maschine...CMD:\n" + self.cmd.replace("BOOTPARAM", "nokaslr oops=panic nopti"),
                     self.qemu_id)
        else:
            log_qemu("Launching Virtual Maschine...", self.qemu_id)
        self.virgin_bitmap = ''.join(chr(0xff) for x in range(self.bitmap_size))

        self.__set_binary(self.binary_filename, self.config.argument_values['executable'], (128 << 20))

        self.cmd = self.cmd.split(" ")
        c = 0
        for i in self.cmd:
            if i == "BOOTPARAM":
                self.cmd[c] = "\"nokaslr oops=panic nopti\""
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

    def __debug_print_timeout(self):
        if self.debug_mode:
            print("[EVENT]  \t" + '\033[1m' + '\033[91m' + "TIMEOUT" + '\033[0m')

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

    def send_rq_set_se_instrumentation(self):
        self.__debug_send(qemu_protocol.REDQUEEN_SET_SE_INSTRUMENTATION)
        self.__debug_recv_expect(qemu_protocol.REDQUEEN_SET_SE_INSTRUMENTATION)

    def send_rq_set_whitelist_instrumentation(self):
        self.__debug_send(qemu_protocol.REDQUEEN_SET_WHITELIST_INSTRUMENTATION)
        self.__debug_recv_expect(qemu_protocol.REDQUEEN_SET_WHITELIST_INSTRUMENTATION)

    def send_rq_update_blacklist(self):
        self.__debug_send(qemu_protocol.REDQUEEN_SET_BLACKLIST)
        self.__debug_recv_expect(qemu_protocol.REDQUEEN_SET_BLACKLIST)

    def __debug_send(self, cmd):
        self.last_bitmap_wrapper.invalidate()
        if self.debug_mode:
            try:
                info = ""
                if self.handshake_stage_1 and cmd == qemu_protocol.RELEASE:
                    info = " (Loader Handshake)"
                    self.handshake_stage_1 = False
                elif self.handshake_stage_2 and cmd == qemu_protocol.RELEASE:
                    info = " (Initial Handshake Iteration)"
                    self.handshake_stage_2 = False
                print("[SEND]  \t" + '\033[94m' + self.CMDS[cmd] + info + '\033[0m')
            except:
                print("[SEND]  \t" + "unknown cmd '" + res + "'")
        self.control.send(cmd)

    def __debug_recv(self):
        while True:
            res = self.control.recv(1)
            if (len(res) == 0):
                log_qemu("__debug_recv error?", self.qemu_id)
                break

            if res == qemu_protocol.PRINTF:
                self.__debug_hprintf()
                self.hprintf_print_mode = False
            else:
                self.hprintf_print_mode = True
                if self.debug_mode:
                    if res == qemu_protocol.ACQUIRE:
                        self.debug_counter = 0
                    # try:
                    info = ""
                    if self.handshake_stage_1 and res == qemu_protocol.RELEASE:
                        info = " (Loader Handshake)"
                    elif self.handshake_stage_2 and res == qemu_protocol.ACQUIRE:
                        info = " (Initial Handshake Iteration)"
                    elif res == qemu_protocol.INFO:
                        print("[RECV]  \t" + '\033[1m' + '\033[92m' + self.CMDS[res] + info + '\033[0m')
                        print("------------------------------------------------------")
                        try:
                            for line in open("/tmp/kAFL_info.txt"):
                                print
                                line,
                            os.remove("/tmp/kAFL_info.txt")
                        except:
                            pass
                        print("------------------------------------------------------")
                        os._exit(0)
                    elif res == qemu_protocol.ABORT:
                        print(common.color.FAIL + self.CMDS[res] + common.color.ENDC)
                        # print("[RECV]  \t" + common.color.FAIL + self.CMDS[res] + common.color.ENDC)
                        os._exit(0)
                    if res == qemu_protocol.CRASH or res == qemu_protocol.KASAN:
                        print("[RECV]  \t" + '\033[1m' + '\033[91m' + self.CMDS[res] + info + '\033[0m')
                    else:
                        print("[RECV]  \t" + '\033[1m' + '\033[92m' + self.CMDS[res] + info + '\033[0m')
                    # except Exception as e:
                    #    print("[RECV]  \t" + "unknown cmd '" + res + "'" + str(e))
                return res

    def __debug_recv_expect(self, cmd):
        res = ''
        while True:

            res = self.__debug_recv()
            if res in cmd:
                break
            elif res is None:
                log_qemu("FAIL New Reload!", self.qemu_id)
                # self.__debug_send(qemu_protocol.RELOAD)
            else:
                # Fixme !!!!!
                log_qemu("FAIL RECV: " + str(res) + "  (Exp: " + str(cmd) + ")", self.qemu_id)
        if res == qemu_protocol.PT_TRASHED:
            log_qemu("PT_TRASHED")
            return False
        return True

    def __del__(self):
        safe_print("killing slave")
        os.system("kill -9 " + str(self.process.pid))

        try:
            if self.process:
                try:
                    self.process.kill()
                except:
                    pass

            if self.e:
                if self.control_fileno:
                    self.e.unregister(self.control_fileno)

            if self.intervm_tty_write:
                self.intervm_tty_write.close()
            # if self.control:
            #    self.control.close()
        except OSError:
            pass

        try:
            self.kafl_shm.close()
        except:
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

        try:
            if self.stat_fd:
                self.stat_fd.close()
        except:
            pass

    def __get_pid_guest_ticks(self):
        if self.stat_fd:
            self.stat_fd.seek(0)
            self.stat_fd.flush()
            return int(self.stat_fd.readline().split(" ")[42])
        return 0

    def __set_binary(self, filename, binaryfile, max_size):
        bin = read_binary_file(binaryfile)
        assert (len(bin) <= max_size)
        atomic_write(filename, bin)

    def set_tick_timeout_treshold(self, treshold):
        self.tick_timeout_treshold = treshold

    def start(self, verbose=False, payload=None):
        if verbose:
            self.process = subprocess.Popen(filter(None, self.cmd),
                                            stdin=None,
                                            stdout=None,
                                            stderr=None)
        else:
            self.process = subprocess.Popen(filter(None, self.cmd),
                                            stdin=subprocess.PIPE,
                                            stdout=subprocess.PIPE,
                                            stderr=None)

        self.stat_fd = open("/proc/" + str(self.process.pid) + "/stat")
        self.init()
        try:
            self.set_init_state(payload=payload)
        except:
            return False
        self.initial_mem_usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        # time.sleep(1)
        self.kafl_shm.seek(0x0)
        self.kafl_shm.write(self.virgin_bitmap)
        # self.kafl_shm.flush()
        return True

    def set_init_state(self, payload=None):
        self.crashed = False
        self.timeout = False
        self.kasan = False
        self.handshake_stage_1 = True
        self.handshake_stage_2 = True
        self.start_ticks = 0
        self.end_ticks = 0

        self.__set_binary(self.binary_filename, self.config.argument_values['executable'], (128 << 20))

        self.__debug_recv_expect(qemu_protocol.RELEASE + qemu_protocol.PT_TRASHED)
        log_qemu("Initial stage 1 handshake done...", self.qemu_id)
        self.__debug_send(qemu_protocol.RELEASE)
        self.__debug_recv_expect(qemu_protocol.ACQUIRE + qemu_protocol.PT_TRASHED)
        log_qemu("Initial stage 2 handshake done...", self.qemu_id)
        if payload:
            self.set_payload(payload)
        self.send_payload(timeout_detection=False, apply_patches=False)
        self.crashed = False
        self.timeout = False
        self.kasan = False

    def init(self):
        self.control = safe_socket(socket.AF_UNIX)
        self.control.settimeout(None)
        self.control.setblocking(1)
        while True:
            try:
                self.control.connect(self.control_filename)
                # self.control.connect(self.control_filename)
                break
            except socket_error:
                pass
                # time.sleep(0.01)

        self.kafl_shm_f = os.open(self.bitmap_filename, os.O_RDWR | os.O_SYNC | os.O_CREAT)
        self.fs_shm_f = os.open(self.payload_filename, os.O_RDWR | os.O_SYNC | os.O_CREAT)

        open(self.tracedump_filename, "wb").close()

        os.symlink(self.tracedump_filename, self.config.argument_values['work_dir'] + "/pt_trace_dump_" + self.qemu_id)

        os.symlink(self.payload_filename, self.config.argument_values['work_dir'] + "/payload_" + self.qemu_id)
        os.symlink(self.bitmap_filename, self.config.argument_values['work_dir'] + "/bitmap_" + self.qemu_id)

        # argv_fd             = os.open(self.argv_filename, os.O_RDWR | os.O_SYNC | os.O_CREAT)
        os.ftruncate(self.kafl_shm_f, self.bitmap_size)
        os.ftruncate(self.fs_shm_f, (128 << 10))
        # os.ftruncate(argv_fd, (4 << 10))

        self.kafl_shm = mmap.mmap(self.kafl_shm_f, self.bitmap_size, mmap.MAP_SHARED, mmap.PROT_WRITE | mmap.PROT_READ)
        self.c_bitmap = (ctypes.c_uint8 * self.bitmap_size).from_buffer(self.kafl_shm)
        self.last_bitmap_wrapper = ExecutionResult(None, None, None, None)
        self.fs_shm = mmap.mmap(self.fs_shm_f, (128 << 10), mmap.MAP_SHARED, mmap.PROT_WRITE | mmap.PROT_READ)

        return True

    def soft_reload(self):
        # log_qemu("soft_reload()", self.qemu_id)
        self.__debug_send(qemu_protocol.RELOAD)
        self.__debug_recv_expect(qemu_protocol.RELOAD)
        success = self.__debug_recv_expect(qemu_protocol.ACQUIRE + qemu_protocol.PT_TRASHED)

        if not success:
            log_qemu("soft reload failed (ipt ovp quirk)", self.qemu_id)
            self.soft_reload()

    def check_recv(self, timeout_detection=True):
        if timeout_detection:
            ready = safe_select([self.control], [], [], 0.25)
            if not ready[0]:
                return 2
        else:
            ready = safe_select([self.control], [], [], 5.0)
            if not ready[0]:
                return 2
        try:
            result = self.__debug_recv()
        except:
            return 2

        if result == qemu_protocol.CRASH:
            return 1
        elif result == qemu_protocol.KASAN:
            return 3
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
        return 0

    def get_bb_delta(self):
        self.fs_shm.seek(0x1F800)

        new_value = struct.unpack("Q", self.fs_shm.read(8))[0]
        delta = new_value - self.bb_count
        self.bb_count = new_value
        return delta

    def send_payload(self, apply_patches=True, timeout_detection=True, max_iterations=10):

        start_time = time.time()
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
        if value == 1:
            self.crashed = True
            self.__debug_recv_expect(qemu_protocol.ACQUIRE)
        elif value == 2:
            self.timeout = True
            self.__debug_print_timeout()

            self.__debug_send(qemu_protocol.RELOAD)
            cmd = self.__debug_recv()
            if cmd == qemu_protocol.RELOAD:
                self.__debug_recv()
            else:
                if (cmd == qemu_protocol.CRASH):
                    self.timeout = False
                    self.crashed = True
                    # self.__debug_recv_expect(qemu_protocol.ACQUIRE)
                    # repeat = not (self.__debug_recv_expect(qemu_protocol.ACQUIRE+qemu_protocol.PT_TRASHED))
                elif (cmd == qemu_protocol.KASAN):
                    self.timeout = False
                    self.kasan = True
                    # self.__debug_recv_expect(qemu_protocol.ACQUIRE)
                    # repeat = not (self.__debug_recv_expect(qemu_protocol.ACQUIRE+qemu_protocol.PT_TRASHED))
                elif (cmd == qemu_protocol.ACQUIRE):
                    self.timeout = False
                    # logger("FALSE POSITIVE TIMEOUT")
                elif cmd == qemu_protocol.PT_TRASHED or cmd == qemu_protocol.PT_TRASHED_CRASH or cmd == qemu_protocol.PT_TRASHED_KASAN:
                    self.repeat = True
                # log_qemu("Error ? (" + str(cmd) + ")", self.qemu_id)
                self.__debug_recv_expect(qemu_protocol.RELOAD)
                repeat = ((not self.__debug_recv_expect(qemu_protocol.ACQUIRE + qemu_protocol.PT_TRASHED)) or repeat)
        elif value == 3:
            self.kasan = True
            self.__debug_recv_expect(qemu_protocol.ACQUIRE)
            # self.soft_reload()
        elif value == 4:
            repeat = True
        elif value == 5:
            repeat = True
            self.soft_reload()
        elif value == 6:
            repeat = True
            self.soft_reload()

        self.needs_execution_for_patches = False

        if repeat:
            if max_iterations != 0:
                self.send_payload(apply_patches=apply_patches, timeout_detection=timeout_detection, max_iterations=0)
                res = self.send_payload(apply_patches=apply_patches, timeout_detection=timeout_detection,
                                        max_iterations=max_iterations - 1)
                res.performance = time.time() - start_time()
                return res

        self.last_bitmap_wrapper = ExecutionResult(self.c_bitmap, self.bitmap_size, self.exit_reason(),
                                                   time.time() - start_time)
        return self.last_bitmap_wrapper

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

    def execute_in_trace_mode(self, debug_mode, timeout_detection):
        log_qemu("Performing trace iteration...", self.qemu_id)
        if debug_mode:
            print("Performing trace iteration...")
        try:
            self.soft_reload()
            self.send_enable_trace()
            self.send_payload(timeout_detection=timeout_detection)
        except Exception as e:
            if debug_mode:
                print("Fail 1...(" + str(e) + ")")
            log_qemu("Fail 1...(" + str(e) + ")", self.qemu_id)
            return False

        try:
            self.soft_reload()
            self.send_disable_trace()
        except Exception as e:
            log_qemu("Fail 3...(" + str(e) + ")", self.qemu_id)
            log_qemu("%s" % traceback.format_exc(), self.qemu_id)
            return False
        return True

    def execute_in_redqueen_mode(self, payload, debug_mode):
        log_qemu("Performing regulare iteration...", self.qemu_id)
        if debug_mode:
            print("Performing regulare iteration...")
        try:
            self.soft_reload()
            self.set_payload(payload)
            self.send_payload()
        except Exception as e:
            if debug_mode:
                print("Fail 1...(" + str(e) + ")")
            log_qemu("Fail 1...(" + str(e) + ")", self.qemu_id)
            return False

        log_qemu("Enabling redqueen mode...", self.qemu_id)
        if debug_mode:
            print("Enabling redqueen mode...")
        try:
            self.soft_reload()
            self.send_rq_set_light_instrumentation()
            self.send_enable_redqueen()
            self.set_payload(payload)
            self.send_payload(timeout_detection=False)
        except Exception as e:
            log_qemu("Fail 3...(" + str(e) + ")", self.qemu_id)
            log_qemu("%s" % traceback.format_exc(), self.qemu_id)
            return False

        log_qemu("Disabling redqueen mode...", self.qemu_id)
        if debug_mode:
            print("Disabling redqueen mode...")
        try:
            self.send_disable_redqueen()
            self.set_payload(payload)
            self.send_payload(timeout_detection=False)
            self.soft_reload()
        except Exception as e:
            log_qemu("Fail 4...(" + str(e) + ")", self.qemu_id)
            log_qemu("%s" % traceback.format_exc(), self.qemu_id)
            return False
        return True

    def modify_payload_size(self, new_size):
        self.fs_shm.seek(0)
        input_len = to_string_32(new_size)
        self.fs_shm.write_byte(input_len[3])
        self.fs_shm.write_byte(input_len[2])
        self.fs_shm.write_byte(input_len[1])
        self.fs_shm.write_byte(input_len[0])

    def copy_master_payload(self, shm, num, size):
        self.fs_shm.seek(0)
        shm.seek(size * num)
        payload = shm.read(size)
        self.fs_shm.write(payload)
        self.fs_shm.write(''.join(chr(0x00) for x in range((64 << 10) - size)))
        # self.fs_shm.flush()
        return payload, size

    def copy_mapserver_payload(self, shm, num, size):
        self.fs_shm.seek(0)
        shm.seek(size * num)
        shm.write(self.fs_shm.read(size))
        # shm.flush()

    def set_payload(self, payload):
        if len(payload) > 65400:
            payload = payload[:65400]
        self.fs_shm.seek(0)
        input_len = to_string_32(len(payload))
        # Fixed
        self.fs_shm.write_byte(input_len[3])
        self.fs_shm.write_byte(input_len[2])
        self.fs_shm.write_byte(input_len[1])
        self.fs_shm.write_byte(input_len[0])
        self.fs_shm.write(payload)
        # self.fs_shm.flush()
