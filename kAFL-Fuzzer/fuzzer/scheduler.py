# Copyright 2019-2020 Intel Corporation
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Funny Experimental Scheduler. Appears better than original kAFL
scheduler especially for slow targets.

Idea is to favorize nodes based on speed, depth, number of new edges. Weights
are tuned such that initial/redq/grim stages are processed first for all fav
nodes, then non-favs start getting processed while at the same time the
high-scoring fav nodes will also go through deterministic stages. Particularly
strong fav nodes may overcome the stage buff and go all the way to havoc before
others are done.

Queue sorting can become a bottleneck on large queues or very fast
execution/finding rate.

"""


from fuzzer.technique.helper import rand
from math import log, log2, ceil

# scale arbitrarily large / small inputs down to interval [1,scale]
# supply alternative log to get a better fit
def log_scale(value, scale=1, base=2):

    if value <= base:
        return 1

    if base == 2:
        val = log2(value)
    else:
        val = log(value, base)

    return ceil(scale*val-scale+1)


class Scheduler:

    def __init__(self):
        pass

    # TODO: node skipping by p(x) conflicts with queue sorting..
    def should_be_scheduled(self, queue, node):
        SKIP_CRASHING_PROB = 80
        SKIP_NONFAV_PROB = 50

        if node.get_exit_reason() != "regular":
            if rand.int(100) < SKIP_CRASHING_PROB:
                return False

        if node.get_state() == "final":
            if not node.get_favorite() and rand.int(100) < SKIP_NONFAV_PROB:
                return False
        return True

    def score_impact(self, node):
        # each fav bit counts 8 times the depth level
        impact = 8*len(node.get_fav_bits()) + node.get_level()
        return log_scale(impact, scale=5)

    def score_speed(self, node):
        p_len = node.get_payload_len()
        p_len = 1 if p_len == 0 else p_len
        return log_scale(10000/(node.get_performance()*p_len), scale=6, base=256)

    def score_priority_favs(self, node):
        score = node.get_fav_factor() # score_speed()

        # below stage buffs are invalid for busy nodes.
        # sort in with <final> nodes as these are the only ones we can process in parallel
        if node.is_busy() or node.get_exit_reason() != "regular":
            return (1, score)

        # boost nodes deeper in the tree
        if node.get_level() > 0:
            score += node.get_level()//5

        # boost nodes with many fav bits
        if len(node.get_fav_bits()) > 0:
            score += 2*len(node.get_fav_bits())

        # TODO: only actually have to compute all this for new nodes and fav bit changes...
        node.set_score(score)

        if node.get_state() in ["initial", "redq/grim"]:
            phase = 256
        elif node.get_state() in ["deterministic"]:
            phase = 8
        elif node.get_state() in ["havoc"]:
            phase = 1
        elif node.get_state() in ["final"]:
            # promote later discovered nodes by compensating for total time spend in havoc.
            # TODO some nodes are buffed on purpose - should only promote based on relative
            # time or cycles rather than total face time
            time_spent = node.node_struct.get("state_time_havoc",1)
            score = score/log_scale(time_spent)
            return (1, score)
        else:
            assert(False), "unknown state"

        # first solve all initial phases, and highest-ranking score/impact there
        return (score*phase, score)

