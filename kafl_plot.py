#!/usr/bin/env python3
#
# Copyright (C) 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright (C) 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Given a kAFL workdir, print an overview of all inputs discovered so far.
Optionally also visualize this output using an xdot graph.

"""

import msgpack
import os
import sys
import time
import glob
import string
from datetime import timedelta
import binascii
from pprint import pprint
import pygraphviz as pgv

import common.color
from common.util import read_binary_file, strdump

class Graph:

    def __init__(self, workdir, outfile):

        self.workdir = workdir
        self.outfile = outfile

        self.dot = pgv.AGraph(directed=True, strict=True)
        self.dot.graph_attr['epsilon'] = '0.0008'
        self.dot.graph_attr['defaultdist'] = '2'
        self.dot.add_node(0, label="Start")
        if self.outfile:
            self.dot.write(self.outfile)

        self.global_startup = time.time()
        self.global_executions = 0
        self.global_runtime = 0
        self.global_tasks = 0


    def process_once(self):

        try:
            for worker_stats in sorted(glob.glob(self.workdir + "/worker_stats_*")):
                self.__process_worker(worker_stats)
            for nodefile in sorted(glob.glob(self.workdir + "/metadata/node_*")):
                self.__process_node(nodefile)
        except:
            print("Error processing stats at given work_dir %s. Aborting." % repr(self.workdir))
            raise

        if self.outfile:
            self.dot.write(self.outfile)
            print("\nOutput written to %s." % self.outfile)

    def flush(self):
        if self.outfile:
            self.dot.write(self.outfile)

    def __read_msgpack(self, name):
        return msgpack.unpackb(read_binary_file(name), strict_map_key=False)

    def __read_payload(self, node_id, exit_reason):
        payload_file = self.workdir + "/corpus/" + exit_reason + "/payload_%05d" % node_id
        return read_binary_file(payload_file)

    def __process_worker(self, worker_stats):

        worker = self.__read_msgpack(worker_stats)
        
        self.global_tasks += 1

        self.global_executions += worker["total_execs"]
        self.global_runtime += worker["run_time"]

        worker_startup = worker["start_time"]
        if worker_startup < self.global_startup:
            self.global_startup = worker_startup

    def __process_node(self, nodefile):

        node = self.__read_msgpack(nodefile)
        node_id = int(nodefile.split("_")[-1])

        payload = self.__read_payload(node_id, node["info"]["exit_reason"])
        sample = strdump(payload)

        plen = node.get("payload_len",1)
        perf = node.get("performance", node["info"]['performance'])
        favs = node.get("fav_bits", "")
        level = node.get("level")
        exit = node["info"]["exit_reason"]
        parent = node["info"]["parent"]
        method = node["info"]["method"]
        stage = node["state"]["name"]
        t_seen = node.get("attention_secs",0)/60

        t_total = node["info"]["time"] - self.global_startup
        t_hours, t_tmp = divmod(t_total, 3600)
        t_mins, t_secs = divmod(t_tmp, 60)
        t_str=('{:02}:{:02}:{:02}'.format(int(t_hours), int(t_mins), int(t_secs)))

        # score as used by new scheduler/queue sorting
        score = node.get("score",0)
        prio = node.get("fav_factor",0)

        if exit == "regular":
            if node["state"]["name"] == "final":
                color = "green"
            else:
                color = "blue"
        elif exit == "crash": color = "red"
        elif exit == "kasan": color = "orange"
        elif exit == "timeout": color = "grey"

        print("%s: Found %3d from %3d using %s [%s] (stage=%s, exit=%s, favs=%d, score=%.1f [%3.1fK, %.2fms], prio=%.1f, t=%.1fmin)" %
                (t_str, node_id, parent, method[:10].ljust(10), sample[:32].ljust(32),
                    stage[:8].ljust(8), exit[:1].title(), len(favs), score, plen/1024, perf*1000, prio, t_seen))

        self.dot.add_node(node["id"], label="%s\n[id=%02d, score=%2.2f]\n%s" % (sample[:12], node_id, score, exit), color=color)
        self.dot.add_edge(parent, node["id"], headlabel=method, arrowhead='open')

        return True

def main(workdir, outfile=None):

    if glob.glob(workdir + "/worker_stats_*") == []:
        print("No kAFL statistics found. Invalid workdir?")

    dot = Graph(workdir, outfile)
    dot.process_once()

if __name__ == "__main__":

    KAFL_ROOT = os.path.dirname(os.path.realpath(__file__)) + "/"
    KAFL_BANNER = KAFL_ROOT + "banner.txt"
    KAFL_CONFIG = KAFL_ROOT + "kafl.ini"

    with open(KAFL_BANNER) as f:
        for line in f:
            print(line.replace("\n", ""))

    print("<< " + common.color.BOLD + common.color.OKGREEN +
            sys.argv[0] + ": kAFL Plotter " + common.color.ENDC + ">>\n")

    if (len(sys.argv) == 2):   main(sys.argv[1])
    elif (len(sys.argv) == 3): main(sys.argv[1], outfile=sys.argv[2])
    else:
        print("Missing arguments. Usage:\n\n\t%s </path/to/workdir> [outfile.dot]\n" % sys.argv[0])
        sys.exit()

