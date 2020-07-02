# Copyright 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
kAFL Master Implementation.

Manage overall fuzz inputs/findings and schedule work for Slave instances.
"""

import glob
import os
from   pprint import pformat
import mmh3

from common.debug import log_master
from common.util import read_binary_file, print_note
from common.execution_result import ExecutionResult
from fuzzer.communicator import ServerConnection, MSG_NODE_DONE, MSG_NEW_INPUT, MSG_READY
from fuzzer.queue import InputQueue
from fuzzer.statistics import MasterStatistics
from fuzzer.technique.redqueen.cmp import enable_hammering
from fuzzer.bitmap import BitmapStorage
from fuzzer.node import QueueNode


class MasterProcess:

    def __init__(self, config):
        self.config = config
        self.comm = ServerConnection(self.config)

        self.busy_events = 0
        self.empty_hash = mmh3.hash(("\x00" * self.config.config_values['BITMAP_SHM_SIZE']), signed=False)


        self.statistics = MasterStatistics(self.config)
        self.queue = InputQueue(self.config, self.statistics)
        self.bitmap_storage = BitmapStorage(config, config.config_values['BITMAP_SHM_SIZE'], "master", read_only=False)

        if self.config.argument_values['hammer_jmp_tables']:
            enable_hammering()

        log_master("Starting (pid: %d)" % os.getpid())
        log_master("Configuration dump:\n%s" %
                pformat(config.argument_values, indent=4, compact=True))

    def send_next_task(self, conn):
        # Inputs placed to imports/ folder have priority.
        # This can also be used to inject additional seeds at runtime.
        imports = glob.glob(self.config.argument_values['work_dir'] + "/imports/*")
        if imports:
            path = imports.pop()
            print("Importing payload from %s" % path)
            seed = read_binary_file(path)
            os.remove(path)
            return self.comm.send_import(conn, {"type": "import", "payload": seed})
        # Process items from queue..
        node = self.queue.get_next()
        if node:
            return self.comm.send_node(conn, {"type": "node", "nid": node.get_id()})

        # No work in queue. Tell slave to wait a little or attempt blind fuzzing.
        # If we see a lot of busy events, check the bitmap and warn on coverage issues.
        self.comm.send_busy(conn)
        self.busy_events +=1
        if self.busy_events >= 10:
            self.busy_events = 0
            main_bitmap = self.bitmap_storage.get_bitmap_for_node_type("regular").c_bitmap
            if mmh3.hash(main_bitmap) == self.empty_hash:
                print_note("Coverage bitmap is empty?! Check -ip0 or try better seeds.")


    def loop(self):
        while True:
            for conn, msg in self.comm.wait(self.statistics.plot_thres):
                if msg["type"] == MSG_NODE_DONE:
                    # Slave execution done, update queue item + send new task
                    log_master("Received results, sending next task..")
                    if msg["node_id"]:
                        self.queue.update_node_results(msg["node_id"], msg["results"], msg["new_payload"])
                    self.send_next_task(conn)
                elif msg["type"] == MSG_NEW_INPUT:
                    # Slave reports new interesting input
                    log_master("Received new input (exit=%s): %s" % (
                        msg["input"]["info"]["exit_reason"], repr(msg["input"]["payload"][:24])))
                    node_struct = {"info": msg["input"]["info"], "state": {"name": "initial"}}
                    self.maybe_insert_node(msg["input"]["payload"], msg["input"]["bitmap"], node_struct)
                elif msg["type"] == MSG_READY:
                    # Initial slave hello, send first task...
                    # log_master("Slave is ready..")
                    self.send_next_task(conn)
                else:
                    raise ValueError("unknown message type {}".format(msg))
            self.statistics.event_slave_poll()
            self.statistics.maybe_write_stats()


    def maybe_insert_node(self, payload, bitmap_array, node_struct):
        bitmap = ExecutionResult.bitmap_from_bytearray(bitmap_array, node_struct["info"]["exit_reason"],
                                                       node_struct["info"]["performance"])
        bitmap.lut_applied = True  # since we received the bitmap from the slave, the lut was already applied
        backup_data = bitmap.copy_to_array()
        should_store, new_bytes, new_bits = self.bitmap_storage.should_store_in_queue(bitmap)
        new_data = bitmap.copy_to_array()
        if should_store:
            node = QueueNode(payload, bitmap_array, node_struct, write=False)
            node.set_new_bytes(new_bytes, write=False)
            node.set_new_bits(new_bits, write=False)
            self.queue.insert_input(node, bitmap)
        else:
            if node_struct["info"]["exit_reason"] != "regular":
                log_master("Payload found to be boring, not saved (exit=%s)" % node_struct["info"]["exit_reason"])
            for i in range(len(bitmap_array)):
                if backup_data[i] != new_data[i]:
                    assert(False), "Bitmap mangled at {} {} {}".format(i, repr(backup_data[i]), repr(new_data[i]))
