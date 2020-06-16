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

from fuzzer.technique.helper import RAND


class GrimoireScheduler:
    def __init__(self):
        self.nodes = []

    def get_next(self):
        if len(self.nodes) > 0:
            return self.nodes.pop(0)
        return None

    def insert_input(self, node):
        if len(node.get_new_bytes()) > 0:
            node.set_state("grimoire_inference")
            self.nodes.append(node)


class Scheduler:

    def __init__(self):
        pass

    def should_be_scheduled(self, queue, node):
        SKIP_TO_NEW_PROB = 99  # ...when there are new, pending favorites
        SKIP_NFAV_OLD_PROB = 95  # ...no new favs, cur entry already fuzzed
        SKIP_NFAV_NEW_PROB = 75  # ...no new favs, cur entry not fuzzed yet

        if node.get_exit_reason() != "regular":
            return False

        if queue.pending_favorites:
            if (node.get_state() == "finished" or not node.get_favorite()) and RAND(100) < SKIP_TO_NEW_PROB:
                return False
        elif not node.get_favorite() and queue.num_inputs() > 10:
            if queue.num_cycles >= 1 and node.get_state() != "finished":
                if RAND(100) < SKIP_NFAV_NEW_PROB:
                    return False
            else:
                if RAND(100) < SKIP_NFAV_OLD_PROB:
                    return False
        return True

    def score_priority(self, node):
        if node.get_performance() == 0:
            return (0,)

        is_fast = 1 if 1 / node.get_performance() >= 150 else 0  # TODO calculate adaptive as fastest n% or similar metric for "fast"

        return (is_fast, len(node.get_fav_bits()), -node.get_level(), -node.get_fav_factor())

    def score_fav(self, node):
        return node.get_performance() * node.get_payload_len()

    def get_attention(node):
        return 1
