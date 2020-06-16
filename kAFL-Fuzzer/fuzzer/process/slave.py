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
import psutil
import time
import traceback

from common.config import FuzzerConfiguration
from common.debug import log_slave, configure_log_prefix
from common.qemu import qemu
from common.safe_syscall import safe_print
from common.util import read_binary_file, atomic_write
from fuzzer.bitmap import BitmapStorage
from fuzzer.bitmap import GlobalBitmap
from fuzzer.communicator import ClientConnection, MSG_NEW_TASK, MSG_QUEUE_STATUS
from fuzzer.node import QueueNode
from fuzzer.state_logic import FuzzingStateLogic
from fuzzer.statistics import SlaveStatistics


def slave_loader(slave_id):
    log_slave("PID: " + str(os.getpid()), slave_id)
    # sys.stdout = open("slave_%d.out"%slave_id, "w")
    config = FuzzerConfiguration()
    if config.argument_values["cpu_affinity"]:
        psutil.Process().cpu_affinity([config.argument_values["cpu_affinity"]])
    else:
        psutil.Process().cpu_affinity([slave_id])
    connection = ClientConnection(slave_id, config)
    slave_process = SlaveProcess(slave_id, config, connection)
    try:
        slave_process.loop()
    except KeyboardInterrupt:
        slave_process.conn.send_terminated()
    log_slave("Killed!", slave_id)


num_fucky = 0


class SlaveProcess:

    def __init__(self, slave_id, config, connection, auto_reload=False):
        self.config = config
        self.slave_id = slave_id
        self.q = qemu(self.slave_id, self.config)
        self.q.start(verbose=False)
        print
        "started qemu"
        self.statistics = SlaveStatistics(self.slave_id, self.config)
        self.logic = FuzzingStateLogic(self, self.config)
        self.conn = connection

        self.bitmap_storage = BitmapStorage(self.config, self.config.config_values['BITMAP_SHM_SIZE'], "master")
        configure_log_prefix("%.2d" % slave_id)

    def handle_server_msg(self, msg):
        if msg["type"] == MSG_NEW_TASK:
            return self.handle_task(msg)
        if msg["type"] == MSG_QUEUE_STATUS:
            return self.handle_queue_status(msg)
        raise "unknown message type {}".format(msg)

    def handle_task(self, msg):
        if msg["task"]["type"] == "import":
            meta_data = {"state": {"name": "import"}}
            payload = msg["task"]["payload"]
        elif msg["task"]["type"] == "node":
            meta_data = QueueNode.get_metadata(msg["task"]["nid"])
            payload = QueueNode.get_payload(meta_data["info"]["exit_reason"], meta_data["id"])
        print
        "slave %d got task %d %s" % (self.slave_id, meta_data.get("node", {}).get("id", -1), repr(meta_data))
        self.statistics.event_task(msg["task"])
        results, new_payload = self.logic.process(payload, meta_data)
        node_id = None
        if new_payload != payload:
            default_info = {"method": "validate_bits", "parent": meta_data["id"]}
            if self.validate_bits(new_payload, meta_data, default_info):
                print("VALIDATE BITS OK")
            else:
                print("VALIDATE BITS FAILED BUG IN TRANSFORMATION!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
                # assert False
        if results:
            node_id = meta_data["id"]
        self.conn.send_task_performed(node_id, results, new_payload)
        # print "performed task"

    def handle_queue_status(self, msg):
        pass

    def loop(self):
        while True:
            # print "client waiting...."
            msg = self.conn.recv()
            # print "got %s"%repr(msg)
            self.handle_server_msg(msg)

    def validate(self, data, old_array):
        self.q.set_payload(data)
        self.statistics.event_exec()
        new_bitmap = self.q.send_payload().apply_lut()
        new_array = new_bitmap.copy_to_array()
        if new_array == old_array:
            print("Validate OK")
            return True, new_bitmap
        else:
            for i in xrange(new_bitmap.bitmap_size):
                if old_array[i] != new_array[i]:
                    safe_print("found fucky bit %d (%d vs %d)" % (i, old_array[i], new_array[i]))
            # assert(False)

        print("VALIDATE FAILED, Not returning a bitmap!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        return False, None

    def validate_bits(self, data, old_node, default_info):
        new_bitmap, _ = self.execute_with_bitmap(data, default_info)
        # handle non-det inputs
        if new_bitmap is None:
            return False
        old_bits = old_node["new_bytes"].copy()
        old_bits.update(old_node["new_bits"])
        return GlobalBitmap.all_new_bits_still_set(old_bits, new_bitmap)

    def validate_bytes(self, data, old_node, default_info):
        new_bitmap, _ = self.execute_with_bitmap(data, default_info)
        # handle non-det inputs
        if new_bitmap is None:
            return False
        old_bits = old_node["new_bytes"].copy()
        return GlobalBitmap.all_new_bits_still_set(old_bits, new_bitmap)

    def execute_redqueen(self, data):
        self.statistics.event_exec_redqueen()
        return self.q.execute_in_redqueen_mode(data, debug_mode=False)

    def execute_with_bitmap(self, data, info):
        bitmap, new_input = self.__execute(data, info)
        return bitmap, new_input

    def execute(self, data, info):
        bitmap, new_input = self.__execute(data, info)
        return new_input

    def __send_to_master(self, data, execution_res, info):
        info["time"] = time.time()
        info["exit_reason"] = execution_res.exit_reason
        info["performance"] = execution_res.performance
        if self.conn is not None:
            self.conn.send_new_input(data, execution_res.copy_to_array(), info)

    def check_fuckyness_and_store_trace(self, data):
        global num_fucky
        exec_res = self.q.send_payload()
        hash = exec_res.hash()
        trace1 = read_binary_file(self.config.argument_values['work_dir'] + "/pt_trace_dump_%d" % self.slave_id)
        exec_res = self.q.send_payload()
        if (hash != exec_res.hash()):
            safe_print("found fucky bits, dumping!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
            num_fucky += 1
            trace_folder = self.config.argument_values['work_dir'] + "/traces/fucky_%d_%d" % (num_fucky, self.slave_id);
            os.makedirs(trace_folder)
            atomic_write(trace_folder + "/input", data)
            atomic_write(trace_folder + "/trace_a", trace1)
            trace2 = read_binary_file(self.config.argument_values["work_dir"] + "/pt_trace_dump_%d" % self.slave_id)
            atomic_write(trace_folder + "/trace_b", trace2)
        return exec_res

    def __execute(self, data, info):
        self.statistics.event_exec()
        self.q.set_payload(data)
        if False:  # Do not emit tracefiles on broken executions
            exec_res = self.check_fuckyness_and_store_trace(data)
        else:
            exec_res = self.q.send_payload()

        is_new_input = self.bitmap_storage.should_send_to_master(exec_res)
        crash = self.execution_exited_abnormally()  # we do not want to validate timeouts and crashes as they tend to be nondeterministic
        if is_new_input:
            if not crash:
                assert exec_res.is_lut_applied()
                bitmap_array = exec_res.copy_to_array()
                valid, exec_res = self.validate(data, bitmap_array)
            if crash or valid:
                self.__send_to_master(data, exec_res, info)
        return exec_res, is_new_input

    def execution_exited_abnormally(self):
        return self.q.crashed or self.q.timeout or self.q.kasan

    # Todo: Fixme
    def __restart_vm(self):
        return True
        if self.comm.slave_termination.value:
            return False
        self.comm.reload_semaphore.acquire()
        try:
            # raise Exception("!")
            # QEMU is full of memory leaks...fixing it that way...
            if self.soft_reload_counter >= 32:
                self.soft_reload_counter = 0
                raise Exception("...")
            self.q.soft_reload()
            self.soft_reload_counter += 1
        except:
            log_slave("restart failed %s" % traceback.format_exc(), self.slave_id)
            while True:
                self.q.__del__()
                self.q = qemu(self.slave_id, self.config)
                if self.q.start():
                    break
                else:
                    time.sleep(0.5)
                    log_slave("Fail Reload", self.slave_id)
        self.comm.reload_semaphore.release()
        self.q.set_tick_timeout_treshold(self.stage_tick_treshold * self.timeout_tick_factor)
        if self.comm.slave_termination.value:
            return False
        return True
