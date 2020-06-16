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

import glob
import os

from common.debug import log_master
from common.util import read_binary_file
from fuzzer.communicator import ServerConnection, MSG_TASK_RESULTS, MSG_NEW_INPUT, MSG_HELLO
from fuzzer.queue import InputQueue
from fuzzer.scheduler import Scheduler
from fuzzer.statistics import MasterStatistics
from fuzzer.technique.helper import random_string
from fuzzer.technique.redqueen.cmp import enable_hammering


class MasterProcess:

    def __init__(self, config):
        self.config = config
        self.comm = ServerConnection(self.config)

        self.scheduler = Scheduler()
        self.statistics = MasterStatistics(self.config)
        self.queue = InputQueue(self.config, self.scheduler, self.statistics)

        self.skip_zero = self.config.argument_values['s']
        self.refresh_rate = self.config.config_values['UI_REFRESH_RATE']
        self.use_effector_map = self.config.argument_values['d']
        self.arith_max = self.config.config_values["ARITHMETIC_MAX"]

        self.mode_fix_checksum = self.config.argument_values["fix_hashes"]

        if not self.config.argument_values['D']:
            self.use_effector_map = False

        if self.config.argument_values['hammer_jmp_tables']:
            enable_hammering()

        print("Master PID: %d\n", os.getpid())
        log_master("Use effector maps: " + str(self.use_effector_map))

    def get_task(self):
        imports = glob.glob(self.config.argument_values['work_dir'] + "/imports/*")
        if imports:
            path = imports.pop()
            payload = read_binary_file(path)
            os.remove(path)
            return {"payload": payload, "type": "import"}
        elif self.queue.has_inputs():
            node = self.queue.get_next()
            return {"type": "node", "nid": node.get_id()}
        else:
            return {"payload": random_string(), "type": "import"}

    def loop(self):
        while True:
            for conn, msg in self.comm.wait():
                if msg["type"] == MSG_TASK_RESULTS:
                    # print repr(msg)
                    if msg["node_id"]:
                        results = msg["results"]
                        if results:
                            node = self.queue.get_node_by_id(msg["node_id"])
                            node.update_metadata(results)
                            new_payload = msg["new_payload"]
                            if new_payload:
                                node.set_payload(new_payload)
                    self.comm.send_task(conn, self.get_task())
                elif msg["type"] == MSG_NEW_INPUT:
                    node_struct = {"info": msg["input"]["info"], "state": {"name": "initial"}}
                    self.queue.maybe_insert_node(msg["input"]["payload"], msg["input"]["bitmap"], node_struct)
                    # print "new input: {}".format(repr(msg["input"]["payload"]))
                elif msg["type"] == MSG_HELLO:
                    print
                    "got CLIENT_HELLO"
                    self.comm.send_task(conn, self.get_task())
                else:
                    raise "unknown message type {}".format(msg)
