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
import tempfile

import lz4.frame as lz4

from common.config import FuzzerConfiguration
from common.log import logger
from common.qemu import qemu
from common.util import read_binary_file, atomic_write
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

    logger.debug(("QEMU-%02d PID: " % slave_id) + str(os.getpid()))
    # sys.stdout = open("slave_%d.out"%slave_id, "w")
    config = FuzzerConfiguration()

    psutil.Process().cpu_affinity([slave_id + config.argument_values["cpu_offset"]])

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
    logger.info("QEMU-%02d Exit." % slave_id)


num_funky = 0
num_crashes = 0

class SlaveProcess:

    def __init__(self, slave_id, config, connection, auto_reload=False):
        self.config = config
        self.slave_id = slave_id
        self.debug_mode = config.argument_values['debug']
        self.q = qemu(self.slave_id, self.config, debug_mode=self.debug_mode)
        self.statistics = SlaveStatistics(self.slave_id, self.config)
        self.logic = FuzzingStateLogic(self, self.config)
        self.conn = connection
        self.work_dir = self.config.argument_values['work_dir']
        self.payload_size_limit = config.config_values['PAYLOAD_SHM_SIZE'] - 5
        self.t_hard = config.argument_values['timeout']
        self.t_soft = config.argument_values['t_soft']
        self.t_check = config.argument_values['t_check']
        self.qemu_logfiles = {'hprintf': self.q.hprintf_logfile,
                              'serial': self.q.serial_logfile}

        self.bitmap_storage = BitmapStorage(self.config, self.config.config_values['BITMAP_SHM_SIZE'], "master")

    def __str__(self):
        return "QEMU-%02d" % self.slave_id

    def handle_import(self, msg):
        meta_data = {"state": {"name": "import"}, "id": 0}
        payload = msg["task"]["payload"]
        self.q.set_timeout(self.t_hard)
        self.logic.process_node(payload, meta_data)
        self.conn.send_ready()

    def handle_busy(self):
        busy_timeout = 4
        kickstart = False

        if kickstart: # spend busy cycle by feeding random strings?
            logger.warn("%s No ready work items, attempting random.." % self)
            start_time = time.time()
            while (time.time() - start_time) < busy_timeout:
                meta_data = {"state": {"name": "import"}, "id": 0}
                payload = rand.bytes(rand.int(32))
                self.q.set_timeout(self.t_hard)
                self.logic.process_node(payload, meta_data)
        else:
            logger.warn("%s No ready work items, waiting..." % self)
            time.sleep(busy_timeout)
        self.conn.send_ready()

    def handle_node(self, msg):
        meta_data = QueueNode.get_metadata(msg["task"]["nid"])
        payload = QueueNode.get_payload(meta_data["info"]["exit_reason"], meta_data["id"])

        # fixme: determine globally based on all seen regulars
        t_dyn = self.t_soft + 1.2 * meta_data["info"]["performance"]
        self.q.set_timeout(min(self.t_hard, t_dyn))

        results, new_payload = self.logic.process_node(payload, meta_data)
        if new_payload:
            default_info = {"method": "validate_bits", "parent": meta_data["id"]}
            if self.validate_bits(new_payload, meta_data, default_info):
                logger.debug("%s Stage %s found alternative payload for node %d"
                          % (self, meta_data["state"]["name"], meta_data["id"]))
            else:
                logger.warn("%s Provided alternative payload found invalid - bug in stage %s?"
                          % (self, meta_data["state"]["name"]))
        self.conn.send_node_done(meta_data["id"], results, new_payload)

    def loop(self):
        if not self.q.start():
            return

        logger.info("%s is ready." % self)
        while True:
            try:
                msg = self.conn.recv()
            except ConnectionResetError:
                logger.error("%s Lost connection to master. Shutting down." % self)
                return

            if self.config.argument_values['log_crashes']:
                # reset logs for each new seed/input
                for _, logfile in self.qemu_logfiles.items():
                    os.truncate(logfile,0)

            if msg["type"] == MSG_RUN_NODE:
                self.handle_node(msg)
            elif msg["type"] == MSG_IMPORT:
                self.handle_import(msg)
            elif msg["type"] == MSG_BUSY:
                self.handle_busy()
            else:
                raise ValueError("Unknown message type {}".format(msg))

    def quick_validate(self, data, old_res, quiet=False, trace=False):
        # Validate in persistent mode. Faster but problematic for very funky targets
        self.statistics.event_exec()
        old_array = old_res.copy_to_array()

        if trace:
            self.q.set_trace_mode(True)
            # give a little extra time in case payload is close to limit
            dyn_timeout = self.q.get_timeout()
            self.q.set_timeout(self.t_hard*2)

        new_res = self.__execute(data).apply_lut()
        new_array = new_res.copy_to_array()

        if trace:
            self.q.set_trace_mode(False)
            self.q.set_timeout(dyn_timeout)

        if new_array == old_array:
            return True, new_res.performance

        if not quiet:
            logger.warn("%s Input validation failed! Target is funky?.." % self)
        return False, new_res.performance

    def funky_validate(self, data, old_res, trace=False):
        # Validate in persistent mode with stochastic prop of funky results

        validations = 8
        confirmations = 0
        runtime_avg = 0
        num = 0
        trace_round=False

        for num in range(validations):
            stable, runtime = self.quick_validate(data, old_res, quiet=True, trace=trace_round)
            if stable:
                confirmations += 1
                runtime_avg += runtime

            if confirmations >= 0.5*validations:
                trace_round=trace

            if confirmations >= 0.75*validations:
                return True, runtime_avg/num

        logger.debug("%s Funky input received %d/%d confirmations. Rejecting.." % (self, confirmations, validations))
        if self.config.argument_values['debug']:
            self.store_funky(data)
        return False, runtime_avg/num

    def store_funky(self, data):
        global num_funky
        num_funky += 1

        # store funky input for further analysis 
        atomic_write(f"%s/funky/payload_%04x%02x" % (self.work_dir, num_funky, self.slave_id), data)


    def __store_crashlogs(self, reason):
        # collect any logs for *new* crash events
        # no real payload IDs here since we don't know them yet
        global num_crashes
        num_crashes += 1

        for logname, logfile in self.qemu_logfiles.items():
            # qemu may keep the FD so we just copy + truncate here and on handle_node()
            shutil.copy(logfile, "%s/logs/%s_%s_%04x%02x.log" % (
                self.work_dir, reason[:5], logname, num_crashes, self.slave_id))
            os.truncate(logfile,0)

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

        if len(data) > self.payload_size_limit:
            data = data[:self.payload_size_limit]
        exec_res = self.q.execute_in_redqueen_mode(data)
        if not exec_res.is_regular():
            self.statistics.event_reload(exec_res.exit_reason)
            self.q.reload()
        return True

    def __send_to_master(self, data, exec_res, info):
        info["time"] = time.time()
        info["exit_reason"] = exec_res.exit_reason
        info["performance"] = exec_res.performance
        info["hash"]        = exec_res.hash()
        info["starved"]     = exec_res.starved
        if self.conn is not None:
            self.conn.send_new_input(data, exec_res.copy_to_array(), info)

    def trace_payload(self, data, info):
        # Legacy implementation of -trace (now -trace_cb) using libxdc_edge_callback hook.
        # This is generally slower and produces different bitmaps so we execute it in
        # a different phase as part of calibration stage.
        # Optionally pickup pt_trace_dump* files as well in case both methods are enabled.
        trace_edge_in = self.work_dir + "/redqueen_workdir_%d/pt_trace_results.txt" % self.slave_id
        trace_dump_in = self.work_dir + "/pt_trace_dump_%d" % self.slave_id
        trace_edge_out = self.work_dir + "/traces/fuzz_cb_%05d.lst" % info['id']
        trace_dump_out = self.work_dir + "/traces/fuzz_cb_%05d.bin" % info['id']

        logger.info("%s Tracing payload_%05d.." % (self, info['id']))

        if len(data) > self.payload_size_limit:
            data = data[:self.payload_size_limit]

        try:
            self.q.set_payload(data)
            old_timeout = self.q.get_timeout()
            self.q.set_timeout(0)
            self.q.set_trace_mode(True)
            exec_res = self.q.send_payload()

            self.q.set_trace_mode(False)
            self.q.set_timeout(old_timeout)

            if (os.path.exists(trace_edge_in)):
                with open(trace_edge_in, 'rb') as f_in:
                    with lz4.LZ4FrameFile(trace_edge_out + ".lz4", 'wb',
                            compression_level=lz4.COMPRESSIONLEVEL_MINHC) as f_out:
                        shutil.copyfileobj(f_in, f_out)

            if (os.path.exists(trace_dump_in)):
                with open(trace_dump_in, 'rb') as f_in:
                    with lz4.LZ4FrameFile(trace_dump_out + ".lz4", 'wb',
                            compression_level=lz4.COMPRESSIONLEVEL_MINHC) as f_out:
                        shutil.copyfileobj(f_in, f_out)

            if not exec_res.is_regular():
                self.statistics.event_reload(exec_res.exit_reason)
                self.q.reload()
        except Exception as e:
            logger.info("%s Failed to produce trace %s: %s (skipping..)" % (self, trace_edge_out, e))
            return None

        return exec_res

    def __execute(self, data, retry=0):

        try:
            self.q.set_payload(data)
            return self.q.send_payload()
        except (ValueError, BrokenPipeError):
            if retry > 2:
                # TODO if it reliably kills qemu, perhaps log to master for harvesting..
                logger.error("%s Aborting due to repeated SHM/socket error." % self)
                if self.debug_mode:
                    logger.debug("%s Payload: %s" % (self, repr(data)))
                    raise
                sys.exit(0)

            logger.warn("%s SHM/socket error (retry %d)" % (self, retry))
            self.statistics.event_reload("shm/socket error")
            if not self.q.restart():
                raise
        return self.__execute(data, retry=retry+1)


    def execute(self, data, info, hard_timeout=False):

        if len(data) > self.payload_size_limit:
            data = data[:self.payload_size_limit]

        exec_res = self.__execute(data)
        self.statistics.event_exec(bb_cov=self.q.bb_seen)

        is_new_input = self.bitmap_storage.should_send_to_master(exec_res, exec_res.exit_reason)
        crash = exec_res.is_crash()
        stable = False

        # -trace_cb causes slower execution and different bitmap computation
        # if both -trace and -trace_cb is provided, we must delay tracing to calibration stage
        trace_pt = self.config.argument_values['trace'] and not self.config.argument_values['trace_cb']

        # store crashes and any validated new behavior
        # do not validate timeouts and crashes at this point as they tend to be nondeterministic
        if is_new_input:
            if not crash:
                assert exec_res.is_lut_applied()

                if self.config.argument_values["funky"]:
                    stable, runtime = self.funky_validate(data, exec_res, trace=trace_pt)
                    exec_res.performance = runtime
                else:
                    stable, runtime = self.quick_validate(data, exec_res, trace=trace_pt)
                    exec_res.performance = (exec_res.performance + runtime)/2

                if trace_pt and stable:
                    trace_in = "%s/pt_trace_dump_%d" % (self.work_dir, self.slave_id)
                    if (os.path.exists(trace_in)):
                        with tempfile.NamedTemporaryFile(delete=False,dir=self.work_dir + "/traces") as f:
                            shutil.move(trace_in, f.name)
                            info['pt_dump'] = f.name
                if not stable:
                    # TODO: auto-throttle persistent runs based on funky rate?
                    self.statistics.event_funky()
            if exec_res.exit_reason == "timeout" and not hard_timeout:
                # re-run payload with max timeout
                # can be quite slow, so we only do this if prior run has some new edges or t_check=True.
                # t_dyn should grow over time and eventually include slower inputs up to max timeout
                maybe_new_regular = self.bitmap_storage.should_send_to_master(exec_res, "regular")
                if self.t_check or maybe_new_regular:
                    dyn_timeout = self.q.get_timeout()
                    self.q.set_timeout(self.t_hard)
                    # if still new, register the payload as regular or (true) timeout
                    exec_res, is_new = self.execute(data, info, hard_timeout=True)
                    self.q.set_timeout(dyn_timeout)
                    if is_new and exec_res.exit_reason != "timeout":
                        logger.debug("Timeout checker found non-timeout with runtime %f >= %f!" % (exec_res.performance, dyn_timeout))
                    else:
                        # uselessly spend time validating a soft-timeout
                        # log it so user may adjust soft-timeout handling
                        self.statistics.event_reload("slow")
                    # sub-call to execute() has submitted the payload if relevant, so we can just return its result here
                    return exec_res, is_new

            if crash and self.config.argument_values['log_crashes']:
                self.__store_crashlogs(exec_res.exit_reason)

            if crash or stable:
                self.__send_to_master(data, exec_res, info)

        # restart Qemu on crash
        if crash:
            self.statistics.event_reload(exec_res.exit_reason)
            self.q.reload()

        return exec_res, is_new_input
