# Copyright 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
kAFL Manager Implementation.

Manage overall fuzz inputs/findings and schedule work for Worker instances.
"""

import glob
import os

import mmh3
import shutil
import msgpack
import lz4.frame as lz4
from pprint import pformat

from kafl_fuzzer.common.logger import logger
from kafl_fuzzer.common.util import read_binary_file
from kafl_fuzzer.manager.communicator import ServerConnection
from kafl_fuzzer.manager.communicator import MSG_NODE_DONE, MSG_NEW_INPUT, MSG_READY, MSG_NODE_ABORT
from kafl_fuzzer.manager.queue import InputQueue
from kafl_fuzzer.manager.statistics import ManagerStatistics
from kafl_fuzzer.manager.bitmap import BitmapStorage
from kafl_fuzzer.manager.node import QueueNode
from kafl_fuzzer.technique.redqueen.cmp import redqueen_global_config
from kafl_fuzzer.worker.execution_result import ExecutionResult

from kafl_fuzzer.technique.helper import helper_init

class ManagerTask:

    def __init__(self, config):
        self.config = config
        self.comm = ServerConnection(self.config)
        self.debug_mode = config.argument_values['debug']
        self.work_dir = self.config.argument_values['work_dir']

        self.busy_events = 0
        self.empty_hash = mmh3.hash(("\x00" * self.config.config_values['BITMAP_SHM_SIZE']), signed=False)

        self.statistics = ManagerStatistics(self.config)
        self.queue = InputQueue(self.config, self.statistics)
        self.bitmap_storage = BitmapStorage(config, config.config_values['BITMAP_SHM_SIZE'], "main", read_only=False)
        self.num_workers = self.config.argument_values['p']

        helper_init()

        redqueen_global_config(
                redq_hammering=self.config.argument_values['hammer_jmp_tables'],
                redq_do_simple=self.config.argument_values['redq_do_simple'],
                afl_arith_max=self.config.config_values['ARITHMETIC_MAX']
                )

        logger.debug("Starting (pid: %d)" % os.getpid())
        #logger.debug("Configuration dump:\n%s" % pformat(config.argument_values, indent=4, compact=True))
        with open(self.work_dir + "/config", 'wb') as fd:
            merged_config = {**self.config.argument_values, **self.config.config_values}
            fd.write(msgpack.packb(merged_config))


    def send_next_task(self, conn):
        # Inputs placed to imports/ folder have priority.
        # This can also be used to inject additional seeds at runtime.
        imports = glob.glob(self.work_dir + "/imports/*")
        if imports:
            path = imports.pop()
            logger.debug("Importing payload from %s" % path)
            seed = read_binary_file(path)
            os.remove(path)
            return self.comm.send_import(conn, {"type": "import", "payload": seed})
        # Process items from queue..
        node = self.queue.get_next()
        if node:
            return self.comm.send_node(conn, {"type": "node", "nid": node.get_id()})

        # No work in queue. Tell Worker to wait a little or attempt blind fuzzing.
        # If all Workers are waiting, check if we are getting any coverage..
        self.comm.send_busy(conn)
        self.busy_events +=1
        if self.busy_events >= self.num_workers:
            self.busy_events = 0
            main_bitmap = self.bitmap_storage.get_bitmap_for_node_type("regular").c_bitmap
            if mmh3.hash(main_bitmap) == self.empty_hash:
                logger.warn("Coverage bitmap is empty?! Check -ip0 or try better seeds.")

    def loop(self):
        while True:
            for conn, msg in self.comm.wait(self.statistics.plot_thres):
                if msg["type"] == MSG_NODE_DONE:
                    # Worker execution done, update queue item + send new task
                    if msg["node_id"]:
                        self.queue.update_node_results(msg["node_id"], msg["results"], msg["new_payload"])
                    self.send_next_task(conn)
                elif msg["type"] == MSG_NODE_ABORT:
                    # Worker execution aborted, update queue item + DONT send new task
                    if msg["node_id"]:
                        self.queue.update_node_results(msg["node_id"], msg["results"], None)
                elif msg["type"] == MSG_NEW_INPUT:
                    # Worker reports new interesting input
                    if self.debug_mode:
                        logger.debug("Received new input (exit=%s): %s" % (
                           msg["input"]["info"]["exit_reason"],
                           repr(msg["input"]["payload"][:24])))
                    node_struct = {"info": msg["input"]["info"], "state": {"name": "initial"}}
                    self.maybe_insert_node(msg["input"]["payload"], msg["input"]["bitmap"], node_struct)
                elif msg["type"] == MSG_READY:
                    # Initial Worker hello, send first task...
                    # logger.debug("Worker is ready..")
                    self.send_next_task(conn)
                else:
                    raise ValueError("unknown message type {}".format(msg))
            self.statistics.maybe_write_stats()
            self.check_abort_condition()


    def check_abort_condition(self):
        import time
        import datetime

        t_limit = self.config.argument_values['abort_time']
        n_limit = self.config.argument_values['abort_exec']
        
        if t_limit:
            if t_limit*3600 < time.time() - self.statistics.data['start_time']:
                raise SystemExit("Exit on timeout.")
        if n_limit:
            if n_limit < self.statistics.data['total_execs']:
                raise SystemExit("Exit on max execs.")

    def store_trace(self, node, tmp_trace):
        if tmp_trace and os.path.exists(tmp_trace):
            trace_dump_out = "%s/traces/fuzz_%05d.bin" % (self.work_dir, node.get_id())
            with open(tmp_trace, 'rb') as f_in:
                with lz4.LZ4FrameFile(trace_dump_out + ".lz4", 'wb',
                        compression_level=lz4.COMPRESSIONLEVEL_MINHC) as f_out:
                    shutil.copyfileobj(f_in, f_out)
            os.remove(tmp_trace)

    def maybe_insert_node(self, payload, bitmap_array, node_struct):
        bitmap = ExecutionResult.bitmap_from_bytearray(bitmap_array, node_struct["info"]["exit_reason"],
                                                       node_struct["info"]["performance"])
        bitmap.lut_applied = True  # since we received the bitmap from Worker, the lut was already applied
        backup_data = bitmap.copy_to_array()
        should_store, new_bytes, new_bits = self.bitmap_storage.should_store_in_queue(bitmap)
        new_data = bitmap.copy_to_array()
        trace_dump_tmp = node_struct["info"].get("pt_dump", None)
        if should_store:
            node = QueueNode(payload, bitmap_array, node_struct, write=False)
            node.set_new_bytes(new_bytes, write=False)
            node.set_new_bits(new_bits, write=False)
            self.queue.insert_input(node, bitmap)
            self.store_trace(node, trace_dump_tmp)
            return

        if trace_dump_tmp and os.path.exists(trace_dump_tmp):
            os.remove(trace_dump_tmp)

        if self.debug_mode:
            logger.debug("Received duplicate payload with exit=%s, discarding." % node_struct["info"]["exit_reason"])
            for i in range(len(bitmap_array)):
                if backup_data[i] != new_data[i]:
                    assert(False), "Bitmap mangled at {} {} {}".format(i, repr(backup_data[i]), repr(new_data[i]))
