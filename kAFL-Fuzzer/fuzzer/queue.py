# Copyright 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Queue of fuzz inputs (nodes). Interface with scheduler to determine next input to be fuzzed.
"""

from fuzzer.scheduler import Scheduler

class InputQueue:
    def __init__(self, config, statistics):
        self.num_slaves = config.argument_values['p']
        self.scheduler = Scheduler()
        self.id_to_node = {}
        self.current_cycle = []
        self.bitmap_index_to_fav_node = {}
        self.num_cycles = 0
        self.statistics = statistics

    def get_next(self, retry=False):
        if len(self.id_to_node) == 0:
            return None

        while self.current_cycle:
            node = self.current_cycle.pop()
            if self.scheduler.should_be_scheduled(self, node):
                if not node.is_busy():
                    if node.get_state() != "final":
                        node.set_busy()
                    return node

        self.update_current_cycle()

        if retry:
            return None
        else:
            return self.get_next(retry=True)

    def update_current_cycle(self):
        # Fun experimental fuzzing scheduler.
        #
        # Idea is to perform a frequent overall sorting of the queue and
        # just fuzz the top-most N entries. This seems effective especially
        # for slow targets since we don't have good queue culling and early
        # Redqueen/Grimoire stages seem to be the most efficient.
        #
        # TODO: Sorting the queue is relatively expensive and can turn the
        # master into a bottleneck. Experiment with cylce_factor to find a nice
        # compromise, or fix Slaves to return less often.
        cycle_factor = 2
        cycle_size = int(cycle_factor*self.num_slaves)

        self.num_cycles += 1
        self.current_cycle = list(self.id_to_node.values())
        self.sort_queue(self.current_cycle)
        self.current_cycle = self.current_cycle[-cycle_size:]
        self.statistics.event_queue_cycle(self)

        #for i in self.current_cycle:
        #    busy = "*" if i.is_busy() else " "
        #    score = i.get_score()
        #    if i.get_state() == "final":
        #        score = score/i.node_struct.get("state_time_havoc")
        #    print("node %02d%s, prio=%2.1f, score=%.2f, perf=%d, stage=%s" %(
        #        i.get_id(),
        #        busy,
        #        i.get_score(),
        #        score,
        #        i.get_fav_factor(),
        #        i.get_state(),
        #        ))

    def sort_queue(self, nodes):
        nodes.sort(key=lambda n: self.scheduler.score_priority_favs(n))

    def get_node_by_id(self, nid):
        return self.id_to_node[nid]

    def num_inputs(self):
        return len(self.id_to_node)

    def maybe_pushback_to_cycle(self, node):
        # put nodes in early stages directly at head of queue, to reduce global sorting
        if node.get_exit_reason() == "regular" and node.get_state() in ["initial"]:
            if len(node.get_fav_bits()) > 20:
                self.current_cycle.append(node)

    def update_node_results(self, nid, results, new_payload):
        node = self.get_node_by_id(nid)
        self.statistics.event_node_update(node, results)
        node.update_metadata(results)
        if new_payload:
            node.set_payload(new_payload)
        node.set_free()
        self.maybe_pushback_to_cycle(node)

    def insert_input(self, node, bitmap):
        parent = node.get_parent_id()
        node.set_level(self.get_node_by_id(parent).get_level() + 1 if parent else 0, write=False)
        node.set_performance(node.get_initial_performance(), write=False)
        node.clear_fav_bits(write=False)
        node.set_fav_factor(self.scheduler.score_speed(node), write=True)

        self.id_to_node[node.get_id()] = node

        # only nodes with new bytes have a chance to become a favorite
        if len(node.get_new_bytes()) > 0:
            self.update_best_input_for_bitmap_entry(node, bitmap)  # TODO improve performance!
            self.maybe_pushback_to_cycle(node)

        self.statistics.event_node_new(node)

    def should_overwrite_old_entry(self, index, val, node):
        entry = self.bitmap_index_to_fav_node.get(index)
        if not entry:
            return True, None
        old_node, old_val = entry
        #more_bits = val > old_val
        better_score = node.get_fav_factor() <= old_node.get_fav_factor()
        if better_score:
            return True, old_node
        return False, None

    def update_best_input_for_bitmap_entry(self, new_node, bitmap):
        changed_nodes = set()
        for (index, val) in enumerate(bitmap.cbuffer):
            if val == 0x0:
                continue
            overwrite, old_node = self.should_overwrite_old_entry(index, val, new_node)
            if overwrite:
                self.bitmap_index_to_fav_node[index] = (new_node, val)
                new_node.add_fav_bit(index, write=False)
                changed_nodes.add(new_node)
                if old_node:
                    old_node.remove_fav_bit(index, write=False)
                    changed_nodes.add(old_node)
                    self.statistics.event_node_remove_fav_bit(old_node)
        for node in changed_nodes:
            node.write_metadata()
