# Copyright 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Manage status outputs for Master and Slave instances
"""

import msgpack
import time
import sys

from common.util import atomic_write, read_binary_file
from common.color import FLUSH_LINE, FAIL, OKBLUE, ENDC

class MasterStatistics:
    def __init__(self, config):
        self.config = config
        self.execs_last = 0
        self.execs_time = 0
        self.plot_last = 0
        self.plot_thres = 5
        self.stat_last = 0
        self.stat_thres = 60*60
        self.write_last = 0
        self.write_thres = 0.5
        self.quiet = self.config.argument_values['quiet']
        self.num_slaves = self.config.argument_values['p']
        self.work_dir = self.config.argument_values['work_dir']
        self.data = {
                "start_time": time.time(),
                "total_execs": 0,
                "num_funky": 0,
                "num_reload": 0,
                "num_timeout": 0,
                "num_slow": 0,
                "max_bb_cov" : 0,
                "paths_total": 0,
                "paths_pending": 0,
                "favs_pending": 0,
                "favs_total": 0,
                "max_level": 0,
                "cycles": 0,
                "bytes_in_bitmap": 0,
                "bytes_worked": 0,
                "yield": {},
                "findings": {
                    "regular": 0,
                    "crash": 0,
                    "kasan": 0,
                    "timeout": 0,
                    },
                "num_slaves": self.num_slaves
                }

        self.stats_file = self.work_dir + "/stats"
        self.plot_file  = self.work_dir + "/stats.csv"
        # write once so that we have a valid stats file
        self.write_plot_header()
        self.maybe_write_stats()

    def read_slave_stats(self, slave_id):
        # one-shot attempt to read + parse file - this can fail!
        filename = self.work_dir + "/slave_stats_%d" % slave_id
        return msgpack.unpackb(read_binary_file(filename), strict_map_key=False)

    def event_queue_cycle(self, queue):
        self.data["cycles"] += 1

    def event_node_new(self, node):
        self.update_yield(node)

        exit = node.get_exit_reason()
        self.data["findings"][exit] += 1

        if exit != "regular":
            self.print_finding_line(node)
            return

        self.data["paths_total"] += 1
        self.data["paths_pending"] += 1

        if node.is_favorite():
            self.data["favs_total"] += 1
            self.data["favs_pending"] += 1

        self.data["bytes_in_bitmap"] += len(node.get_new_bytes())
        self.data["max_level"] = max(node.get_level(), self.data["max_level"])

        self.print_finding_line(node)

    def print_finding_line(self, node):

        if not sys.stdout.isatty() or self.quiet:
            return

        node_id = node.get_id()
        plen = node.get_payload_len()
        perf = node.get_performance()
        favs = len(node.get_fav_bits())
        new_bytes = len(node.get_new_bytes())
        new_bits = len(node.get_new_bits())
        parent = node.get_parent_id()
        method = node.get_method()

        t_total = node.get_timestamp() - self.data["start_time"]
        t_hours, t_tmp = divmod(t_total, 3600)
        t_mins, t_secs = divmod(t_tmp, 60)
        t_str=('{:02}:{:02}:{:02}'.format(int(t_hours), int(t_mins), int(t_secs)))

        exit = node.get_exit_reason()[:1].title()
        if exit == "R":
            PREFIX = FLUSH_LINE
        elif exit == "T":
            PREFIX = FLUSH_LINE + OKBLUE
        else:
            PREFIX = FLUSH_LINE + FAIL

        print(PREFIX + "%s: Got %4d from %4d: exit=%s, %2d/%2d bits, %2d favs, %1.2fmsec, %1.1fKB (%s)%s"
                % (t_str, node_id, parent, exit, new_bytes, new_bits, favs, perf*1000, plen/1024, method[:12], ENDC))
        self.print_status_line()

    def print_status_line(self, keep_line=False):

        t_total = time.time() - self.data["start_time"]
        t_hours, t_tmp = divmod(t_total, 3600)
        t_mins, t_secs = divmod(t_tmp, 60)
        t_str=('{:02}:{:02}:{:02}'.format(int(t_hours), int(t_mins), int(t_secs)))
        execs = self.data["total_execs"] / t_total

        print(FLUSH_LINE + "%s: %5d exec/s, %4d edges, %2.0f%% favs pending, findings: <%d, %d, %d>" % (
            t_str,
            execs,
            #self.data["paths_total"],
            self.data["bytes_in_bitmap"],
            self.data["favs_pending"]*100/max(1,self.data["favs_total"]),
            self.data["findings"]["crash"],
            self.data["findings"]["kasan"],
            self.data["findings"]["timeout"]),
            end="\n" if keep_line else "\r")


    def event_node_remove_fav_bit(self, node):
        # called when queue manager removed a fav bit from an existing node.
        # check if that was the last fav and maybe update #fav_pending count
        if not node.is_favorite():
            self.data["favs_total"] -= 1
            if node.get_state() != "final":
                self.data["favs_pending"] -= 1

    def event_slave_poll(self):
        # collect some global stats - not pretty but simplifies write_plot and kafl_gui
        sum_execs = 0
        sum_funky = 0
        sum_reload = 0
        sum_timeout = 0
        sum_slow = 0
        max_bb_cov = 0
        try:
            for slave_id in range(0, self.num_slaves):
                sum_execs  += self.read_slave_stats(slave_id).get("total_execs", 0)
                sum_funky  += self.read_slave_stats(slave_id).get("num_funky", 0)
                sum_reload += self.read_slave_stats(slave_id).get("num_reload", 0)
                sum_timeout += self.read_slave_stats(slave_id).get("num_timeout", 0)
                sum_slow    += self.read_slave_stats(slave_id).get("num_slow", 0)
                max_bb_cov = max(max_bb_cov,
                                 self.read_slave_stats(slave_id).get("bb_seen", 0))
        except:
            return # don't update on read failure
        self.data["total_execs"] = sum_execs
        self.data["num_funky"]   = sum_funky
        self.data["num_reload"]  = sum_reload
        self.data["num_timeout"] = sum_timeout
        self.data["num_slow"]    = sum_slow
        self.data["max_bb_cov"]  = max_bb_cov

    def event_node_update(self, node, update):
        if update.get("state", None):
            if update.get("state", None).get("name", None) == "final":
                if node.get_state() == "havoc":
                    self.data["paths_pending"] -= 1
                    if node.is_favorite():
                        self.data["favs_pending"] -= 1

    def update_yield(self, node):
        method = node.node_struct["info"]["method"] # TODO: add node.get_method() API
        if method not in self.data["yield"]:
            self.data["yield"][method] = 0
        self.data["yield"][method] += 1

    def maybe_write_stats(self):
        cur_time = time.time()

        if cur_time - self.write_last > self.write_thres:
            self.write_last = cur_time
            self.event_slave_poll()
            self.write_statistics()
            if sys.stdout.isatty():
                if cur_time - self.stat_last > self.stat_thres:
                    self.stat_last = cur_time
                    self.print_status_line(keep_line=True)
                else:
                    self.print_status_line(keep_line=False)

            if cur_time - self.plot_last > self.plot_thres:
                self.plot_last = cur_time
                self.write_plot()

    def write_statistics(self):
        atomic_write(self.stats_file, msgpack.packb(self.data))
        #print "execs/sec: %d" % ((self.data["executions"] + self.data["executions_redqueen"]) / self.data["duration"])

    def write_plot_header(self):
        with open(self.plot_file, 'a') as fd:
            fd.write("#secs; exec/s; paths; p_pend; favs; crash; kasan; tmout; lvls; cycles; f_pend; exec; edges\n")

    def write_plot(self):
        cur_time = time.time()
        run_time = cur_time - self.data["start_time"]
        cur_speed = (self.data["total_execs"] - self.execs_last)/(cur_time-self.execs_time)
        self.execs_last = self.data["total_execs"]
        self.execs_time = cur_time
        with open(self.plot_file, 'a') as fd:
            fd.write("%06d;%d;%d;%d;%d;%d;%d;%d;%d;%d;%d;%d;%d\n" % (
                run_time,                      # elapsed time
                cur_speed,                     # execs/sec
                self.data["paths_total"],      # paths total
                self.data["paths_pending"],    # paths pending
                self.data["favs_total"],       # favs total
                self.data["findings"]["crash"],# unique crashes
                self.data["findings"]["kasan"],# unique kasan
                self.data["findings"]["timeout"], # unique timeout
                self.data["max_level"],        # max level
                self.data["cycles"],           # cycles
                self.data["favs_pending"],     # favs pending
                self.data["total_execs"],      # current total execs
                self.data["bytes_in_bitmap"],  # unique edges (minus collisions)
                ))


class SlaveStatistics:
    def __init__(self, slave_id, config):
        self.config = config
        self.filename = self.config.argument_values['work_dir'] + "/slave_stats_%d" % (slave_id)
        self.write_last = 0
        self.write_thres = 0.5
        self.execs_new = 0
        self.data = {
            "start_time": time.time(),
            "run_time": 0,
            "total_execs": 0,
            "execs/sec": 0,
            "bb_seen" : 0,
            "num_reload": 0,
            "num_funky": 0,
            "num_timeout": 0,
            "num_slow": 0,
            "executions_redqueen": 0,
            "node_id": 0,
        }
        # write once so that we have a valid stats file
        self.maybe_write_stats()

    def event_stage(self, stage, nid):
        self.data["stage"] = stage
        self.data["node_id"] = nid
        self.maybe_write_stats()

    def event_method(self, method):
        self.data["method"] = method
        self.maybe_write_stats()

    def event_exec(self, bb_cov=0):
        if self.data["bb_seen"] < bb_cov:
            self.data["bb_seen"] = bb_cov
        self.execs_new += 1
        self.maybe_write_stats()

    def event_reload(self, reason):
        self.data["num_reload"] += 1
        if reason == "timeout":
            self.data["num_timeout"] += 1
        if reason == "slow":
            self.data["num_slow"] += 1
        self.maybe_write_stats()

    def event_funky(self):
        self.data["num_funky"] += 1
        self.maybe_write_stats()

    def event_exec_redqueen(self):
        self.data["executions_redqueen"] += 1
        self.maybe_write_stats()

    def get_total_execs(self):
        return self.data["total_execs"]

    def maybe_write_stats(self):
        cur_time = time.time()
        if cur_time - self.write_last < self.write_thres:
            return

        self.data["run_time"] = cur_time - self.data["start_time"]
        self.data["execs/sec"] = self.execs_new // (cur_time - self.write_last)
        self.data["total_execs"] += self.execs_new
        self.execs_new = 0

        atomic_write(self.filename, msgpack.packb(self.data))
        #print "execs/sec: %d" % ((self.data["executions"] + self.data["executions_redqueen"]) / self.data["duration"])
        self.write_last = cur_time
