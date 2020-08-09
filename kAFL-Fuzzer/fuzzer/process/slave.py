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
import shutil

import lz4.frame as lz4

from common.config import FuzzerConfiguration
from common.debug import log_slave
from common.qemu import qemu
from common.util import read_binary_file, atomic_write, print_warning, print_fail
from fuzzer.bitmap import BitmapStorage, GlobalBitmap
from fuzzer.communicator import ClientConnection, MSG_IMPORT, MSG_RUN_NODE, MSG_BUSY
from fuzzer.node import QueueNode
from fuzzer.state_logic import FuzzingStateLogic
from fuzzer.statistics import SlaveStatistics
from fuzzer.technique.helper import rand


def slave_loader(slave_id):

    def sigterm_handler(signal, frame):
        if slave_process.q:
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

    def quick_validate(self, data, old_res, quiet=False):
        # Validate in persistent mode. Faster but problematic for very funky targets
        self.statistics.event_exec()
        old_array = old_res.copy_to_array()

        new_res = self.__execute(data).apply_lut()
        new_array = new_res.copy_to_array()

        if new_array == old_array:
            return True

        if not quiet:
            log_slave("Input validation failed! Target is funky?..", self.slave_id)
        return False

    def funky_validate(self, data, old_res):
        # Validate in persistent mode with stochastic prop of funky results

        validations = 8
        confirmations = 0
        for _ in range(validations):
            if self.quick_validate(data, old_res, quiet=True):
                confirmations += 1

        if confirmations >= 0.8*validations:
            return True

        log_slave("Funky input received %d/%d confirmations. Rejecting.." % (confirmations, validations), self.slave_id)
        self.store_funky(data)
        return False

    def store_funky(self, data):
        global num_funky
        num_funky += 1

        # store funky input for further analysis 
        funky_folder = self.config.argument_values['work_dir'] + "/funky/"
        atomic_write(funky_folder + "input_%02d_%05d" % (self.slave_id, num_funky), data)

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

    def __send_to_master(self, data, execution_res, info):
        info["time"] = time.time()
        info["exit_reason"] = execution_res.exit_reason
        info["performance"] = execution_res.performance
        if self.conn is not None:
            self.conn.send_new_input(data, execution_res.copy_to_array(), info)

    def trace_payload(self, data, info):
        trace_file_in = self.config.argument_values['work_dir'] + "/redqueen_workdir_%d/pt_trace_results.txt" % self.slave_id;
        trace_folder = self.config.argument_values['work_dir'] + "/traces/"
        trace_file_out = trace_folder + "payload_%05d" % info['id']

        log_slave("Tracing payload_%05d.." % info['id'], self.slave_id)

        try:
            self.q.set_payload(data)
            exec_res = self.q.execute_in_trace_mode(timeout_detection=False)

            with open(trace_file_in, 'rb') as f_in:
                with lz4.LZ4FrameFile(trace_file_out + ".lz4", 'wb', compression_level=lz4.COMPRESSIONLEVEL_MINHC) as f_out:
                    shutil.copyfileobj(f_in, f_out)

            if not exec_res.is_regular():
                self.statistics.event_reload()
                self.q.reload()
        except Exception as e:
            log_slave("Failed to produce trace %s: %s (skipping..)" % (trace_file_out, e), self.slave_id)
            return None

        return exec_res

    def __execute(self, data, retry=0):

        try:
            self.q.set_payload(data)
            return self.q.send_payload()
        except (ValueError, BrokenPipeError):
            if retry > 2:
                # TODO if it reliably kills qemu, perhaps log to master for harvesting..
                print_fail("Slave %d aborting due to repeated SHM/socket error. Check logs." % self.slave_id)
                log_slave("Aborting due to repeated SHM/socket error. Payload: %s" % repr(data), self.slave_id)
                raise
            print_warning("SHM/socket error on Slave %d (retry %d)" % (self.slave_id, retry))
            log_slave("SHM/socket error, trying to restart qemu...", self.slave_id)
            self.statistics.event_reload()
            if not self.q.restart():
                raise
        return self.__execute(data, retry=retry+1)


    def execute(self, data, info):
        self.statistics.event_exec()

        exec_res = self.__execute(data)

        is_new_input = self.bitmap_storage.should_send_to_master(exec_res)
        crash = exec_res.is_crash()
        stable = False;

        # store crashes and any validated new behavior
        # do not validate timeouts and crashes at this point as they tend to be nondeterministic
        if is_new_input:
            if not crash:
                assert exec_res.is_lut_applied()
                if self.config.argument_values["funky"]:
                    stable = self.funky_validate(data, exec_res)
                else:
                    stable = self.quick_validate(data, exec_res)

                if not stable:
                    # TODO: auto-throttle persistent runs based on funky rate?
                    self.statistics.event_funky()
            if crash or stable:
                self.__send_to_master(data, exec_res, info)
        else:
            if crash:
                log_slave("Crashing input found (%s), but not new (discarding)" % (exec_res.exit_reason), self.slave_id)

        # restart Qemu on crash
        if crash:
            self.statistics.event_reload()
            self.q.reload()

        return exec_res, is_new_input
