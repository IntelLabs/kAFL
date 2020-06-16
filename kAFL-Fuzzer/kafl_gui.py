#!/usr/bin/python
# -*- coding: utf-8 -*-
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

import curses
import string
import msgpack
import os
import sys
import inotify.adapters
import glob
import psutil
from pprint import pprint
from common.util import read_binary_file
from threading import Thread, Lock

import sys


class Interface:
    def __init__(self, stdscr):
        self.stdscr = stdscr
        self.y = 0

    def print_title_line(self, title):
        title = "[%s%s]" % (title, " " * (len(title) % 2))
        pad = "=" * ((80 - len(title)) / 2)
        self.stdscr.addstr(self.y, 0, pad + title + pad)
        self.y += 1

    def print_sep_line(self):
        self.stdscr.addstr(self.y, 0, "=" * 80)
        self.y += 1

    def print_thin_line(self):
        self.stdscr.addstr(self.y, 0, "-" * 80)
        self.y += 1

    def print_empty(self):
        self.stdscr.addstr(self.y, 0, " " * 80)
        self.y += 1

    def print_info_line(self, pairs, sep=" | ", end="|", prefix="|"):
        infos = map(lambda (minlen, key, val): ("%s: %s" % (key, val)).ljust(minlen), pairs)
        if len(infos) == 0:
            infos = [""]
        space_used = (len(infos) - 1) * len(sep) + sum(map(len, infos)) + len(end) + len(prefix)
        self.stdscr.addstr(self.y, 0, prefix + sep.join(infos) + end)
        self.y += 1

    def refresh(self):
        self.y = 0
        self.stdscr.refresh()

    def clear(self):
        self.stdscr.clear()

    def print_hexdump(self, data, old_data=None, max_rows=10):
        width = 16
        num_rows = min(max_rows, len(data) / width + 1)
        for ri in xrange(0, max_rows):
            row = data[width * ri:width * (ri + 1)]
            if len(row):
                self.print_hexrow(row, offset=ri * width)
            else:
                self.print_empty()

    def print_hexrow(self, row, old_row=None, offset=0):
        def map_printable(s_char):
            if s_char in string.printable and s_char not in "\t\n\r\x0b\x0c":
                return s_char
            else:
                return "."

        def map_hex(s_char):
            return hex(ord(s_char))[2:].ljust(2, "0")

        prefix = "|0x%07x: " % offset
        hex_dmp = prefix + (" ".join(map(map_hex, row)))
        hex_dmp = hex_dmp.ljust(59)
        print_dmp = ("".join(map(map_printable, row)))
        print_dmp = print_dmp.ljust(16)
        print_dmp = " | " + print_dmp + " |"
        self.stdscr.addstr(self.y, 0, hex_dmp)
        self.stdscr.addstr(self.y, len(hex_dmp), print_dmp)
        self.y += 1


def pnum(int):
    assert (int >= 0)
    if int <= 9999:
        return "%5d" % int
    int /= 1000.0
    if int <= 99:
        return "%.1fK" % int
    int /= 1000.0
    if int <= 99:
        return "%.1fM" % int
    int /= 1000.0
    if int <= 99:
        return "%.1fG" % int
    int /= 1000.0
    if int <= 99:
        return "%.1fT" % int
    int /= 1000.0
    if int <= 99:
        return "%.1fP" % int
    assert (False)


def pfloat(flt):
    assert (flt >= 0)
    if flt <= 999:
        return "%.1f" % flt
    return pnum(flt)


def ptime(secs):
    if not secs:
        return "None yet"
    secs = int(secs)
    seconds = secs % 60
    secs /= 60
    mins = secs % 60
    secs /= 60
    hours = secs % 24
    days = secs / 24
    if days > 0:
        return "%0.2dd,%0.2dh" % (days, hours)
    if hours > 0:
        return "%0.2dh,%0.2dm" % (hours, mins)
    return "%0.2dm,%0.2ds" % (mins, seconds)


class GuiDrawer:
    def __init__(self, workdir, stdscr):
        self.gui_mutex = Lock()
        curses.start_color()
        curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_BLACK)
        curses.init_pair(2, curses.COLOR_GREEN, curses.COLOR_BLACK)
        curses.init_pair(3, curses.COLOR_YELLOW, curses.COLOR_BLACK)
        curses.init_pair(4, curses.COLOR_RED, curses.COLOR_BLACK)
        default_col = curses.color_pair(1)

        # Fenster und Hintergrundfarben
        stdscr.bkgd(default_col)
        stdscr.refresh()
        self.gui = Interface(stdscr)
        self.stdscr = stdscr
        self.current_slave_id = 0

        self.finished = False
        self.data = GuiData(workdir)
        self.watcher = Thread(target=self.watch, args=(workdir,))
        self.cpu_watcher = Thread(target=self.watch_cpu, args=())
        self.loop = Thread(target=self.loop, args=())
        self.watcher.daemon = True
        self.watcher.start()
        self.cpu_watcher.daemon = True
        self.cpu_watcher.start()
        self.loop.start()
        self.loop.join()

    def draw(self):
        d = self.data
        self.gui.print_title_line("RedQueen")
        self.gui.print_info_line([(37, "Target", d.target()), (38, "Config", d.config())])
        self.gui.print_thin_line()
        self.gui.print_info_line([(17, "Coverage", pnum(d.coverage())), (17, "Regular", pnum((d.num_regular()))),
                                  (17, "Crash", pnum(d.num_crash())), (18, "Timeout", pnum(d.num_timeout()))])
        self.gui.print_info_line([(17, "Last", ptime(d.time_since_last())), (17, "Last", ptime(d.time_since_regular())),
                                  (17, "Last", ptime(d.time_since_crash())),
                                  (18, "Last", ptime(d.time_since_timeout()))])
        self.gui.print_info_line([(17, "Runtime", ptime(d.runtime())), (17, "Execs/s", pnum(d.execs_p_sec())),
                                  (17, "#Execs", pnum(d.total_execs())), (18, "#Slaves", pnum(d.num_slaves()))])
        self.gui.print_info_line(
            [(17, "P(Collis)", pnum(d.p_coll()) + "%"), (17, "Fav Pend.", pfloat(d.pending_fav()) + "%"),
             (17, "Cycles", pnum(d.cycles())), (18, "Stability", pfloat(d.stability()) + "%")])
        self.gui.print_info_line([(12, "Total", pnum(d.total_cpu()) + "%"), (17, "Logic", pfloat(d.logic_cpu()) + "%"),
                                  (17, "VM", pfloat(d.vm_cpu()) + "%"), (18, "QEMU", pfloat(d.qemu_cpu()) + "%")],
                                 prefix="|CPU ")
        self.gui.print_info_line([(12, "Total", pnum(d.total_mem()) + "%"), (17, "Logic", pfloat(d.logic_mem()) + "%"),
                                  (17, "VM", pfloat(d.vm_mem()) + "%"), (18, "QEMU", pfloat(d.qemu_mem()) + "%")],
                                 prefix="|MEM ")
        self.gui.print_thin_line()
        self.gui.print_info_line(
            [(12, "Color", pnum(d.yield_color())), (0, "Trim", pnum(d.yield_trim())), (13, "Redq", pnum(d.yield_rq())),
             (13, "Hvc", pnum(d.yield_havoc())), (12, "Det", pnum(d.yield_det()))], prefix="|Yld: ")
        self.gui.print_info_line(
            [(0, "Total", pnum(d.fav_total())), (0, "Init", pnum(d.fav_init())), (13, "Gram", pnum(d.fav_gram())),
             (13, "Hvc", pnum(d.fav_havoc())), (12, "Fin", pnum(d.fav_fin()))], prefix="|Fav: ")
        self.gui.print_info_line([(0, "Total", pnum(d.normal_total())), (0, "Init", pnum(d.normal_init())),
                                  (13, "Gram", pnum(d.normal_gram())), (13, "Hvc", pnum(d.normal_havoc())),
                                  (12, "Fin", pnum(d.normal_fin()))], prefix="|Nrm: ")
        self.gui.print_info_line([(0, "Total", pnum(d.bitmap_size())), (0, "Used", pnum(d.bitmap_used())),
                                  (29, "P(Collision)", pfloat(d.p_coll()) + "%"),
                                  (12, "#Bits", pfloat(d.bits_per_byte()))], prefix="|Bmp: ")
        self.gui.print_sep_line()
        for i in range(0, d.num_slaves()):
            hl = " "
            if i == self.current_slave_id:
                hl = ">"
            self.gui.print_info_line([(14, "Stage", d.slave_stage(i)), (15, "e/s", pnum(d.slave_execs_p_sec(i))),
                                      (14, "size", pnum(d.slave_input_size(i)) + "B"),
                                      (14, "lvl", pnum(d.slave_level(i)))], prefix="|%c Slave %d | " % (hl, i))

        i = self.current_slave_id
        old_data = ["1324567890___________________", "1324567890abcdefghijkl_________"]
        data = d.slave_payload(i)
        self.gui.print_title_line("Slave %d" % i)
        self.gui.print_info_line(
            [(0, "Input ID ", "%8d" % d.slave_input_id(i)), (12, "#Fav", pnum(d.slave_fav_bits(i))),
             (12, "#Bytes", pnum(d.slave_new_bytes(i))), (12, "#Bits", pnum(d.slave_new_bits(i))),
             (10, "exit", d.slave_exit_reason(i))])
        self.gui.print_info_line([(0, "Parent ID", "%8d" % d.slave_input_parent_id(i)), (
        28, "Attention", pnum(d.slave_attention_execs(i)) + "e / " + ptime(d.slave_attention_seconds(i))),
                                  (25, "found", ptime(d.slave_input_found_at(i)))])
        self.gui.print_thin_line()
        self.gui.print_hexdump(data, old_data=old_data, max_rows=10)
        self.gui.print_title_line("Log")
        self.gui.refresh()

    def loop(self):
        d = self.data
        while True:
            char = self.stdscr.getch()
            self.gui_mutex.acquire()
            try:
                if char == curses.KEY_UP:
                    self.current_slave_id = (self.current_slave_id - 1) % d.num_slaves()
                elif char == curses.KEY_DOWN:
                    self.current_slave_id = (self.current_slave_id + 1) % d.num_slaves()
                elif char == ord("q") or char == ord("Q"):
                    self.finished = True
                    return
                self.draw()
            finally:
                self.gui_mutex.release()

    def watch(self, workdir):
        d = self.data
        mask = inotify.constants.IN_MODIFY | inotify.constants.IN_MOVED_TO | inotify.constants.IN_CREATE
        self.inotify = inotify.adapters.Inotify()
        i = self.inotify
        i.add_watch(workdir + "/stats", mask)
        for slave in glob.glob(workdir + "/slave_stats_*"):
            i.add_watch(slave, mask)
        i.add_watch(workdir + "/metadata/", mask)

        for event in i.event_gen(yield_nones=False):
            if self.finished:
                return
            self.gui_mutex.acquire()
            try:
                (_, type_names, path, filename) = event
                d.update(path + "/" + filename)
                self.draw()
            finally:
                self.gui_mutex.release()

    def watch_cpu(self):
        while True:
            if self.finished:
                return
            cpu_info = psutil.cpu_times_percent(interval=1, percpu=False)
            mem_info = psutil.virtual_memory()
            self.gui_mutex.acquire()
            try:
                self.data.mem = mem_info
                self.data.cpu = cpu_info
                self.draw()
            finally:
                self.gui_mutex.release()


class GuiData:

    def __init__(self, workdir):
        self.workdir = workdir
        self.load_initial()
        pass

    def load_initial(self):
        self.cpu = psutil.cpu_times_percent(interval=0.01, percpu=False)
        self.mem = psutil.virtual_memory()
        self.stats = self.read_file("stats")
        self.slave_stats = map(lambda x: {}, glob.glob(self.workdir + "/slave_stats_*"))
        for slave_id in range(0, len(self.slave_stats)):
            self.slave_stats[slave_id] = self.read_file("slave_stats_%d" % slave_id)

        self.nodes = {}
        for metadata in glob.glob(self.workdir + "/metadata/node_*"):
            self.load_node(metadata)
        self.aggregate()

    def load_node(self, name):
        node_id = int(name.split("_")[-1])
        self.nodes[node_id] = self.read_file("metadata/node_%05d" % node_id)

    def aggregate(self):
        self.aggregated = {
            "fav_states": {},
            "normal_states": {},
            "exit_reasons": {"regular": 0, "crash": 0, "kasan": 0, "timeout": 0}
        }
        for nid in self.nodes:
            node = self.nodes[nid]
            self.aggregated["exit_reasons"][node["info"]["exit_reason"]] += 1
            if node["info"]["exit_reason"] == "regular":
                states = self.aggregated["normal_states"]
                if len(node["fav_bits"]) > 0:
                    states = self.aggregated["fav_states"]
                nodestate = node["state"]["name"]
                states[nodestate] = states.get(nodestate, 0) + 1

    def target(self):
        return "readelf"

    def config(self):
        return "rq_nodet"

    def runtime(self):
        return max(map(lambda x: x["duration"], self.slave_stats))

    def execs_p_sec(self):
        num_execs = 0
        for slave_info in self.slave_stats:
            num_execs += slave_info["execs/sec"]
        return num_execs

    def total_execs(self):
        num_execs = 0
        for slave_info in self.slave_stats:
            num_execs += slave_info["executions"]
        return num_execs

    def num_slaves(self):
        return len(self.slave_stats)

    def coverage(self):
        return 0

    def num_regular(self):
        return self.aggregated["exit_reasons"]["regular"]

    def num_crash(self):
        return self.aggregated["exit_reasons"]["crash"]

    def num_timeout(self):
        return self.aggregated["exit_reasons"]["timeout"]

    def num_asan(self):
        return self.aggregated["exit_reasons"]["kasan"]

    def time_since_last(self):
        return min([self.time_since_crash(), self.time_since_regular(), self.time_since_timeout()])

    def time_since_crash(self):
        return None

    def time_since_regular(self):
        return None

    def time_since_timeout(self):
        return None

    def pending_fav(self):
        if self.fav_total() > 0:
            return 100 * (self.fav_total() - self.fav_fin()) / float(self.fav_total())
        return 0

    def stability(self):
        return 0.0

    def cycles(self):
        return self.stats["queue"].get("cycles", 0)

    def total_cpu(self):
        return self.cpu.user + self.cpu.guest

    def logic_cpu(self):
        return self.cpu.user

    def vm_cpu(self):
        return self.cpu.guest

    def qemu_cpu(self):
        return 0

    def total_mem(self):
        return 100 * float(self.mem.used) / float(self.mem.total)

    def logic_mem(self):
        return 0

    def vm_mem(self):
        return 0

    def qemu_mem(self):
        return 0

    def yield_color(self):
        return self.stats["yield"].get("colorization", 0)

    def yield_trim(self):
        return self.stats["yield"].get("trim", 0)

    def yield_rq(self):
        return self.stats["yield"].get("redqueen", 0)

    def yield_havoc(self):
        return self.stats["yield"].get("havoc", 0)

    def yield_det(self):
        return self.stats["yield"].get("det", 0)

    def normal_total(self):
        return self.normal_init() + self.normal_gram() + self.normal_havoc() + self.normal_fin()

    def normal_init(self):
        return self.aggregated["normal_states"].get("initial", 0)

    def normal_gram(self):
        return self.aggregated["normal_states"].get("grammar", 0)

    def normal_havoc(self):
        return self.aggregated["normal_states"].get("havoc", 0)

    def normal_fin(self):
        return self.aggregated["normal_states"].get("finished", 0)

    def fav_total(self):
        return self.fav_init() + self.fav_gram() + self.fav_havoc() + self.fav_fin()

    def fav_init(self):
        return self.aggregated["fav_states"].get("initial", 0)

    def fav_gram(self):
        return self.aggregated["fav_states"].get("grammar", 0)

    def fav_havoc(self):
        return self.aggregated["fav_states"].get("havoc", 0)

    def fav_fin(self):
        return self.aggregated["fav_states"].get("finished", 0)

    def bitmap_size(self):
        return 64 * 1024

    def bitmap_used(self):
        return self.stats["bytes_in_bitmap"]

    def p_coll(self):
        return 100.0 * float(self.bitmap_used()) / float(self.bitmap_size())

    def bits_per_byte(self):
        return 0

    def slave_stage(self, i):
        return self.nodes[self.slave_input_id(i)]["state"]["name"][0:6]

    def slave_execs_p_sec(self, i):
        return self.slave_stats[i].get("execs/sec")

    def slave_input_size(self, i):
        return self.nodes[self.slave_input_id(i)]["payload_len"]

    def slave_level(self, i):
        return self.nodes[self.slave_input_id(i)]["level"]

    def slave_input_id(self, i):
        return self.slave_stats[i]["node_id"]

    def slave_input_parent_id(self, i):
        return self.nodes[self.slave_input_id(i)]["info"]["parent"]

    def slave_fav_bits(self, i):
        return len(self.nodes[self.slave_input_id(i)]["fav_bits"])

    def slave_new_bytes(self, i):
        return len(self.nodes[self.slave_input_id(i)]["new_bytes"])

    def slave_new_bits(self, i):
        return len(self.nodes[self.slave_input_id(i)]["new_bits"])

    def slave_exit_reason(self, i):
        return self.nodes[self.slave_input_id(i)]["info"]["exit_reason"][0]

    def slave_attention_execs(self, i):
        return 0

    def slave_attention_seconds(self, i):
        return 0

    def slave_input_found_at(self, i):
        return 0

    def slave_payload(self, i):
        nid = self.slave_input_id(i)
        exit_reason = self.nodes[nid]["info"]["exit_reason"]
        return read_binary_file(self.workdir + "/corpus/%s/payload_%05d" % (exit_reason, nid))[
               0:1024]  # TODO remove path traversal vuln

    def load_slave(self, id):
        self.slave_stats[id] = self.read_file("slave_stats_%d" % id)

    def load_global(self):
        self.stats = self.read_file("stats")

    def update(self, changed_file):
        if "node" in changed_file.split("/")[-1]:
            self.load_node(changed_file)
            self.aggregate()
        else:
            for i in xrange(0, self.num_slaves()):
                self.load_slave(i)
            self.load_global()

    def read_file(self, name):
        return msgpack.unpackb(read_binary_file(self.workdir + "/" + name))

    def read_meta(id):
        pass


def main(stdscr):
    GuiDrawer(sys.argv[1], stdscr)


if (len(sys.argv) == 2):
    curses.wrapper(main)
else:
    print("Usage: " + sys.argv[0] + " <kafl-workdir>")
