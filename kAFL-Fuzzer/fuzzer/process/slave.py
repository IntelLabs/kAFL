# Copyright 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
kAFL Slave Implementation.

Request fuzz input from Master and process it through various fuzzing stages/mutations.
Each Slave is associated with a single Qemu instance for executing fuzz inputs.
"""

import os
import psutil
import time
import signal
import sys

from common.config import FuzzerConfiguration
from common.debug import log_slave
from common.qemu import qemu
from common.util import read_binary_file, atomic_write, print_warning
from fuzzer.bitmap import BitmapStorage, GlobalBitmap
from fuzzer.communicator import ClientConnection, MSG_IMPORT, MSG_RUN_NODE, MSG_BUSY
from fuzzer.node import QueueNode
from fuzzer.state_logic import FuzzingStateLogic
from fuzzer.statistics import SlaveStatistics
from fuzzer.technique.helper import rand


def slave_loader(slave_id):

    def sigterm_handler(signal, frame):
        slave_process.q.async_exit()
        sys.exit(0)


    log_slave("PID: " + str(os.getpid()), slave_id)
    # sys.stdout = open("slave_%d.out"%slave_id, "w")
    config = FuzzerConfiguration()

    if config.argument_values["cpu_affinity"]:
        psutil.Process().cpu_affinity([config.argument_values["cpu_affinity"]])
    else:
        psutil.Process().cpu_affinity([slave_id])

    connection = ClientConnection(slave_id, config)

    slave_process = SlaveProcess(slave_id, config, connection)

    signal.signal(signal.SIGTERM, sigterm_handler)
    os.setpgrp()

    try:
        slave_process.loop()
    except:
        if slave_process.q:
            slave_process.q.async_exit()
        raise
    log_slave("Exit.", slave_id)


num_funky = 0

class SlaveProcess:

    def __init__(self, slave_id, config, connection, auto_reload=False):
        self.config = config
        self.slave_id = slave_id
        self.q = qemu(self.slave_id, self.config)
        self.statistics = SlaveStatistics(self.slave_id, self.config)
        self.logic = FuzzingStateLogic(self, self.config)
        self.conn = connection

        self.bitmap_storage = BitmapStorage(self.config, self.config.config_values['BITMAP_SHM_SIZE'], "master")

    def handle_import(self, msg):
        meta_data = {"state": {"name": "import"}, "id": 0}
        payload = msg["task"]["payload"]
        self.logic.process_node(payload, meta_data)
        self.conn.send_ready()

    def handle_busy(self):
        busy_timeout = 1
        kickstart = False

        if kickstart: # spend busy cycle by feeding random strings?
            log_slave("No ready work items, attempting random..", self.slave_id)
            start_time = time.time()
            while (time.time() - start_time) < busy_timeout:
                meta_data = {"state": {"name": "import"}, "id": 0}
                payload = rand.bytes(rand.int(32))
                self.logic.process_node(payload, meta_data)
        else:
            log_slave("No ready work items, waiting...", self.slave_id)
            time.sleep(busy_timeout)
        self.conn.send_ready()

    def handle_node(self, msg):
        meta_data = QueueNode.get_metadata(msg["task"]["nid"])
        payload = QueueNode.get_payload(meta_data["info"]["exit_reason"], meta_data["id"])

        results, new_payload = self.logic.process_node(payload, meta_data)
        if new_payload:
            default_info = {"method": "validate_bits", "parent": meta_data["id"]}
            if self.validate_bits(new_payload, meta_data, default_info):
                log_slave("Stage %s found alternative payload for node %d"
                          % (meta_data["state"]["name"], meta_data["id"]),
                          self.slave_id)
            else:
                log_slave("Provided alternative payload found invalid - bug in stage %s?"
                          % meta_data["state"]["name"],
                          self.slave_id)
        self.conn.send_node_done(meta_data["id"], results, new_payload)

    def loop(self):
        if not self.q.start():
            return

        log_slave("Started qemu", self.slave_id)
        while True:
            try:
                msg = self.conn.recv()
            except ConnectionResetError:
                log_slave("Lost connection to master. Shutting down.", self.slave_id)
                return

            if msg["type"] == MSG_RUN_NODE:
                self.handle_node(msg)
            elif msg["type"] == MSG_IMPORT:
                self.handle_import(msg)
            elif msg["type"] == MSG_BUSY:
                self.handle_busy()
            else:
                raise ValueError("Unknown message type {}".format(msg))

    def validate(self, data, old_array):
        self.q.set_payload(data)
        self.statistics.event_exec()
        new_bitmap = self.q.send_payload().apply_lut()
        new_array = new_bitmap.copy_to_array()
        if new_array == old_array:
            return True, new_bitmap

        log_slave("Validation failed, ignoring this input", self.slave_id)
        if False: # activate detailed logging of funky bitmaps
            for i in range(new_bitmap.bitmap_size):
                if old_array[i] != new_array[i]:
                    log_slave("Funky bit in validation bitmap: %d (%d vs %d)"
                            % (i, old_array[i], new_array[i]), self.slave_id)

        return False, None

    def validate_bits(self, data, old_node, default_info):
        new_bitmap, _ = self.execute(data, default_info)
        # handle non-det inputs
        if new_bitmap is None:
            return False
        old_bits = old_node["new_bytes"].copy()
        old_bits.update(old_node["new_bits"])
        return GlobalBitmap.all_new_bits_still_set(old_bits, new_bitmap)

    def validate_bytes(self, data, old_node, default_info):
        new_bitmap, _ = self.execute(data, default_info)
        # handle non-det inputs
        if new_bitmap is None:
            return False
        old_bits = old_node["new_bytes"].copy()
        return GlobalBitmap.all_new_bits_still_set(old_bits, new_bitmap)

    def execute_redqueen(self, data):
        self.statistics.event_exec_redqueen()
        return self.q.execute_in_redqueen_mode(data)

    def __execute(self, data, retry=0):

        try:
            self.q.set_payload(data)
            if False:  # activate detailed comparison of execution traces?
                return self.check_funkyness_and_store_trace(data)
            else:
                return self.q.send_payload()
        except BrokenPipeError:
            if retry > 2:
                # TODO if it reliably kills qemu, perhaps log to master for harvesting..
                log_slave("Fatal: Repeated BrokenPipeError on input: %s" % repr(data), self.slave_id)
                raise
            else:
                log_slave("BrokenPipeError, trying to restart qemu...", self.slave_id)
                self.q.shutdown()
                time.sleep(1)
                self.q.start()
                return self.__execute(data, retry=retry+1)

        assert False


    def __send_to_master(self, data, execution_res, info):
        info["time"] = time.time()
        info["exit_reason"] = execution_res.exit_reason
        info["performance"] = execution_res.performance
        if self.conn is not None:
            self.conn.send_new_input(data, execution_res.copy_to_array(), info)

    def check_funkyness_and_store_trace(self, data):
        global num_funky
        exec_res = self.q.send_payload()
        hash = exec_res.hash()
        trace1 = read_binary_file(self.config.argument_values['work_dir'] + "/pt_trace_dump_%d" % self.slave_id)
        exec_res = self.q.send_payload()
        if (hash != exec_res.hash()):
            print_warning("Validation identified funky bits, dumping!")
            num_funky += 1
            trace_folder = self.config.argument_values['work_dir'] + "/traces/funky_%d_%d" % (num_funky, self.slave_id);
            os.makedirs(trace_folder)
            atomic_write(trace_folder + "/input", data)
            atomic_write(trace_folder + "/trace_a", trace1)
            trace2 = read_binary_file(self.config.argument_values["work_dir"] + "/pt_trace_dump_%d" % self.slave_id)
            atomic_write(trace_folder + "/trace_b", trace2)
        return exec_res

    def execute(self, data, info):
        self.statistics.event_exec()

        exec_res = self.__execute(data)

        is_new_input = self.bitmap_storage.should_send_to_master(exec_res)
        crash = self.execution_exited_abnormally()

        # store crashes and any validated new behavior
        # do validate timeouts and crashes at this point as they tend to be nondeterministic
        if is_new_input:
            if not crash:
                assert exec_res.is_lut_applied()
                bitmap_array = exec_res.copy_to_array()
                valid, exec_res = self.validate(data, bitmap_array)
                if not valid:
                    self.statistics.event_funky()
                    log_slave("Input validation failed, throttling N/A", self.slave_id)

                    # TODO: the funky event is already over at this point and the error may indeed not be deterministic
                    # how about we store some $num funky payloads for more focused exploration rather than discarding them?
                    #exec_res.exit_reason = 'funky'
                    #self.__send_to_master(data, exec_res, info)
            if crash or valid:
                self.__send_to_master(data, exec_res, info)
        else:
            if crash:
                log_slave("Crashing input found (%s), but not new (discarding)" % (exec_res.exit_reason), self.slave_id)

        # restart Qemu on crash
        if crash:
            self.statistics.event_reload()
            self.q.restart()

        return exec_res, is_new_input

    def execution_exited_abnormally(self):
        return self.q.crashed or self.q.timeout or self.q.kasan
