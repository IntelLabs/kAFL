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

Additionally, the time that a node has already spent in fuzzing is used to
dynamically reduce its score. This means new found nodes will be prioritized
until they reached similar attention time in relation to their basic
performance/impact score. Also slow nodes that easily lead to timeouts/crashes
will be de-emphasized faster as their attention time compensates for the early
stage buff.

Queue sorting can become a bottleneck on large queues or very fast
execution/finding rate.
"""

from math import log, log2, log10, ceil

from kafl_fuzzer.common import logger

# scale arbitrarily large / small inputs down to interval [1,scale]
# supply alternative log to get a better fit
def log_scale(value, base=2):

    if base == 2:
        return log2(base+value)
    elif base == 10:
        return log10(base+value)
    else:
        return log(base+value, base)


class Scheduler:

    def score_impact(self, node):
        # compute payload priority based on fav bits and perf score
        return 10*log_scale(len(node.get_fav_bits())) / log_scale(node.get_score())

    def score_speed(self, node):
        # payload runtime * length, lower is better
        # apply log scale such that notable changes in KB or msec lead to different score
        # resulting score granuarily should work well as bucket size for favs filtering
        min_time=1/1000
        p_time = log_scale(node.get_performance() / min_time)
        p_len  = log_scale(node.get_payload_len() / 1024)
        return ceil(p_time*p_len)

    def score_priority_favs(self, node):
        # assign scheduler priority based on prio, and special stage/type buffs
        # consider total time already spend on this node to promote later discovered nodes
        prio = node.get_fav_factor()
        time_spent = node.node_struct.get("attention_secs",0) / 60
        time_buff = log_scale(time_spent)

        # assign special buff based on node type or stage
        if node.get_exit_reason() != "regular":
            phase = 1/10
        elif node.is_busy():
            # avoid filling priority list with busy nodes
            phase = 1
        elif node.get_state() in ["initial"]:
            phase = 16
        elif node.get_state() in ["redq/grim"]:
            phase = 8
        elif node.get_state() in ["deterministic"]:
            phase = 4
        elif node.get_state() in ["havoc"]:
            phase = 2
        elif node.get_state() in ["final"]:
            phase = 1
        else:
            assert(False), "unknown state"

        if not node.is_favorite():
            phase /= 5

        #logger.info(
        #        "%s: node %3d rated %5.2f [phase=%3d, prio=%.2f, tbuff=%.2f]" % (
        #            "Sched", node.get_id(), prio*phase/time_buff, phase, prio, time_buff))
        return prio*phase/time_buff

