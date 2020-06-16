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

from common.execution_result import ExecutionResult
from common.safe_syscall import safe_print
from fuzzer.bitmap import BitmapStorage
from fuzzer.node import QueueNode
from fuzzer.scheduler import GrimoireScheduler


class InputQueue:
    def __init__(self, config, scheduler, statistics):
        self.config = config
        self.scheduler = scheduler
        self.bitmap_storage = BitmapStorage(config, config.config_values['BITMAP_SHM_SIZE'], "master", read_only=False)
        self.id_to_node = {}
        self.current_cycle = []
        self.bitmap_index_to_fav_node = {}
        self.num_cycles = 0
        self.pending_favorites = True
        self.statistics = statistics
        self.grimoire_scheduler = GrimoireScheduler()

    def get_next(self):
        assert self.id_to_node

        gram = self.grimoire_scheduler.get_next()
        if gram:
            return gram

        node = self.current_cycle.pop() if self.current_cycle else None
        while node:
            if self.scheduler.should_be_scheduled(self, node):
                return node
            node = self.current_cycle.pop() if self.current_cycle else None
        self.update_current_cycle()
        return self.get_next()

    def has_inputs(self):
        return len(self.id_to_node) > 0

    def update_current_cycle(self):
        self.num_cycles += 1
        self.current_cycle = list(self.id_to_node.values())
        self.cull_queue(self.current_cycle)
        self.sort_queue(self.current_cycle)
        self.statistics.event_queue_cycle(self)

    def cull_queue(self, nodes):
        self.pending_favorites = False
        for (index, (node, _)) in self.bitmap_index_to_fav_node.iteritems():
            if node.get_state() != "finished":
                self.pending_favorites = True
        # TODO implement queue culling like afl?

    def sort_queue(self, nodes):
        nodes.sort(key=lambda n: self.scheduler.score_priority(n))

    def get_node_by_id(self, id):
        return self.id_to_node[id]

    def num_inputs(self):
        len(self.id_to_node)

    def construct_node(self, payload, bitmap, new_bytes, new_bits, node_struct, ):
        assert "fav_bits" not in node_struct
        assert "level" not in node_struct
        assert "new_bytes" not in node_struct
        assert "new_bits" not in node_struct
        node_struct["new_bytes"] = new_bytes
        node_struct["new_bits"] = new_bits

        node = QueueNode(payload, bitmap, node_struct, write=False)
        node.clear_fav_bits(write=False)
        parent = node_struct["info"]["parent"]
        node.set_level(self.get_node_by_id(parent).get_level() + 1 if parent else 0, write=False)
        return node

    def maybe_insert_node(self, payload, bitmap_array, node_struct):
        bitmap = ExecutionResult.bitmap_from_bytearray(bitmap_array, node_struct["info"]["exit_reason"],
                                                       node_struct["info"]["performance"])
        bitmap.lut_applied = True  # since we received the bitmap from the slave, the lut was already applied
        backup_data = bitmap.copy_to_array()
        should_store, new_bytes, new_bits = self.bitmap_storage.should_store_in_queue(bitmap)
        new_data = bitmap.copy_to_array()
        if should_store:
            self.insert_input(self.construct_node(payload, bitmap_array, new_bytes, new_bits, node_struct), bitmap)
        else:
            for i in xrange(len(bitmap_array)):
                if backup_data[i] != new_data[i]:
                    print("diffing at {} {} {}".format(i, repr(backup_data[i]), repr(new_data[i])))
            safe_print("RECIEVED BORING INPUT, NOT SAVING..")
            # assert(False)

    def insert_input(self, node, bitmap):
        safe_print(repr(node.node_struct))
        self.grimoire_scheduler.insert_input(node)
        node.set_fav_factor(self.scheduler.score_fav(node), write=True)
        self.id_to_node[node.get_id()] = node
        self.current_cycle.append(node)
        print("saving input")
        self.update_best_input_for_bitmap_entry(node, bitmap)  # TODO improve performance!
        print("done saving input")
        self.sort_queue(self.current_cycle)

        self.statistics.event_new_node_found(node)

    def should_overwrite_old_entry(self, index, val, node):
        entry = self.bitmap_index_to_fav_node.get(index)
        if not entry:
            return True, None
        old_node, old_val = entry
        more_bits = val > old_val
        better_score = (val == old_val and node.get_fav_factor() < old_node.get_fav_factor())
        if more_bits or better_score:
            return True, old_node
        return False, None

    def update_best_input_for_bitmap_entry(self, node, bitmap):
        changed_nodes = set()
        for (index, val) in enumerate(bitmap.cbuffer):
            if val == 0x0:
                continue
            overwrite, old_node = self.should_overwrite_old_entry(index, val, node)
            if overwrite:
                self.bitmap_index_to_fav_node[index] = (node, val)
                node.add_fav_bit(index, write=False)
                changed_nodes.add(node)
                if old_node:
                    old_node.remove_fav_bit(index, write=False)
                    changed_nodes.add(old_node)
        for node in changed_nodes:
            node.write_metadata()
