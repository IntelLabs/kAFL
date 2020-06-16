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

import msgpack
import time

from common.util import atomic_write


class MasterStatistics:
    def __init__(self, config):
        self.config = config
        self.data = {
            "yield": {},
            "queue": {
                "cycles": 0,
                "states": {}
            },
            "bytes_in_bitmap": 0,
        }
        self.filename = self.config.argument_values['work_dir'] + "/stats"

    def event_queue_cycle(self, queue):
        data_states = self.data["queue"]["states"] = {}
        self.data["queue"]["cycles"] += 1
        for id in queue.id_to_node:
            node = queue.id_to_node[id]
            state = node.get_state()
            data_states = self.data["queue"]["states"]
            if state not in data_states:
                data_states[state] = 0
            data_states[state] += 1
        self.write_statistics()

    def event_new_node_found(self, node):
        self.update_bitmap_bytes(node)
        self.update_yield(node)
        self.update_inputs(node)

        self.write_statistics()

    def update_inputs(self, node):
        exitreason = node.get_exit_reason()
        if not exitreason in self.data["queue"]:
            self.data["queue"][exitreason] = {
                "num": 0,
                "last_found": None
            }
        info = self.data["queue"][exitreason]
        info["num"] += 1
        info["last_found"] = time.ctime(node.node_struct["info"]["time"])

    def update_bitmap_bytes(self, node):
        self.data["bytes_in_bitmap"] += len(node.node_struct["new_bytes"])

    def update_yield(self, node):
        method = node.node_struct["info"]["method"]
        if method not in self.data["yield"]:
            self.data["yield"][method] = 0
        self.data["yield"][method] += 1

    def write_statistics(self):
        atomic_write(self.filename, msgpack.packb(self.data))


class SlaveStatistics:
    def __init__(self, slave_id, config):
        self.config = config
        self.filename = self.config.argument_values['work_dir'] + "/slave_stats_%d" % (slave_id)
        self.data = {
            "start_time": time.time(),
            "executions": 0,
            "executions_redqueen": 0,
            "node_id": None,
        }

    def event_task(self, task):
        self.data["node_id"] = task.get("nid", None)
        self.write_statistics()

    def event_exec(self):
        self.data["executions"] += 1
        if self.data["executions"] % 1000 == 0:
            self.write_statistics()

    def event_exec_redqueen(self):
        self.data["executions_redqueen"] += 1

    def write_statistics(self):
        self.data["duration"] = time.time() - self.data["start_time"]
        self.data["execs/sec"] = (self.data["executions"] + self.data["executions_redqueen"]) / self.data["duration"]
        atomic_write(self.filename, msgpack.packb(self.data))
