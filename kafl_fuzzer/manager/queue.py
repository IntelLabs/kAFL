# Copyright 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Queue of fuzz inputs (nodes). Interface with scheduler to determine next input to be fuzzed.
"""

from kafl_fuzzer.manager.scheduler import Scheduler
from kafl_fuzzer.common.logger import logger

class InputQueue:
    def __init__(self, config, statistics):
        self.num_workers = config.processes
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
        # Issues
        # - Sorting the queue is relatively expensive, can turn the Manager into a bottleneck
        # - If we have very few items, we will end up sorting all the time
        #
        # Alternatives?
        # - keep a sorted queue
        # - let scheduler pick randomly, with weighted distribution

        fav_items = self.statistics.data['favs_total']
        cycle_size = int(min(1.5*fav_items, 4*self.num_workers))

        full_queue = sorted(self.id_to_node.values(),
                            key=lambda n: self.scheduler.score_priority_favs(n))

        self.num_cycles += 1
        self.current_cycle = full_queue[-cycle_size:]
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

    def maybe_pushback_to_cycle(self, node):
        # put nodes in early stages directly at head of queue, to reduce global sorting
        if node.get_exit_reason() == "regular" and node.get_state() in ["initial"]:
            if len(node.get_fav_bits()) > 20:
                self.current_cycle.append(node)

    def update_node_results(self, nid, results, new_payload):
        node = self.id_to_node[nid]
        self.statistics.event_node_update(node, results)
        if new_payload:
            node.set_payload(new_payload)
            node.node_struct["info"]["trimmed"] = True
            node.set_score(self.scheduler.score_speed(node))
        if results.get("performance"):
            oldperf = node.get_initial_performance()
            newperf = results["performance"]
            #print("perf updated for node %d: %.2f => %.2f" % (node.get_id(), oldperf*1000,newperf*1000))
            node.set_score(self.scheduler.score_speed(node))

        node.set_fav_factor(self.scheduler.score_impact(node), write=False)
        node.update_metadata(results)
        node.set_free()
        self.maybe_pushback_to_cycle(node)

    def insert_input(self, node, bitmap):
        parent = node.get_parent_id()
        node.set_level(self.id_to_node[parent].get_level() + 1 if parent else 0, write=False)
        node.set_performance(node.get_initial_performance(), write=False)
        node.clear_fav_bits(write=False)
        node.set_score(self.scheduler.score_speed(node))

        self.id_to_node[node.get_id()] = node

        # only regular nodes with new bytes can become favorites
        if node.get_exit_reason() == "regular":
            if len(node.get_new_bytes()) > 0:
                self.update_best_input_for_bitmap_entry(node, bitmap)  # TODO improve performance!
                self.maybe_pushback_to_cycle(node)

        node.set_fav_factor(self.scheduler.score_impact(node), write=True)
        #node.update_file()
        self.statistics.event_node_new(node)

    def should_overwrite_old_entry(self, index, val, node):
        entry = self.bitmap_index_to_fav_node.get(index)
        if not entry:
            return True, None
        old_node, old_val = entry
        better_bits = val > old_val and node.get_score() <= old_node.get_score()
        better_score = val == old_val and node.get_score() < old_node.get_score()
        if better_bits or better_score:
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
                #changed_nodes.add(new_node)
                if old_node:
                    old_node.remove_fav_bit(index, write=False)
                    changed_nodes.add(old_node)
                    self.statistics.event_node_remove_fav_bit(old_node)
        for node in changed_nodes:
            node.set_fav_factor(self.scheduler.score_impact(node), write=False)
            node.update_file()
