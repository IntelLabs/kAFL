#!/usr/bin/env python3
#
# Copyright (C) 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright (C) 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Given a kAFL workdir, produce a text-based UI with status summary/overview.
"""

import curses
import string
import msgpack
import os
import sys
import time
import inotify.adapters
import glob
import psutil
import locale

from common.util import read_binary_file
from threading import Thread, Lock

class Interface:
    def __init__(self, stdscr):
        self.stdscr = stdscr
        self.y = 0

    def print_title_line(self, title):
        title = "[%s%s]" % (title, " " * (len(title) % 2))
        pad = '░' * ((80 - len(title)) // 2)
        self.stdscr.addstr(self.y, 0, pad + title + pad)
        self.y += 1

    def print_sep_line(self):
        self.stdscr.addstr(self.y, 0, '━' * 80)
        self.y += 1

    def print_thin_line(self):
        self.stdscr.addstr(self.y, 0, '─' * 80)
        self.y += 1

    def print_empty(self):
        self.stdscr.addstr(self.y, 0, '┃' + ' ' * 78 + '┃')
        self.y += 1

    def print_info_line(self, pairs, sep=" │ ", end="┃", prefix=""):
        infos = []
        for info in pairs:
            infolen = len(info[1]) + len(info[2])
            if infolen == 0:
                infos.append(" ".ljust(info[0]+1))
            else:
                infos.append("%s:%s%s" % (
                    info[1], " ".ljust(info[0]-infolen), info[2]))

        self.stdscr.addstr(self.y, 0, '┃' + prefix + sep.join(infos) + " " + end)
        self.y += 1

    def refresh(self):
        self.y = 0
        self.stdscr.refresh()

    def clear(self):
        self.stdscr.clear()

    def print_hexdump(self, data, max_rows=10):
        width = 16
        for ri in range(0, max_rows):
            row = data[width * ri:width * (ri + 1)]
            if len(row) > 0:
                self.print_hexrow(row, offset=ri * width)
            else:
                self.print_empty()

    def print_hexrow(self, row, offset=0):
        def map_printable(char):
            s_char = chr(char)
            if s_char in string.printable and s_char not in "\t\n\r\x0b\x0c":
                return s_char
            return "."

        def map_hex(char):
            return hex(char)[2:].ljust(2, "0")

        prefix = "┃0x%07x: " % offset
        hex_dmp = prefix + (" ".join(map(map_hex, row)))
        hex_dmp = hex_dmp.ljust(61)
        print_dmp = ("".join(map(map_printable, row)))
        print_dmp = print_dmp.ljust(16)
        print_dmp = "│" + print_dmp + " ┃"
        self.stdscr.addstr(self.y, 0, hex_dmp)
        self.stdscr.addstr(self.y, len(hex_dmp), print_dmp)
        self.y += 1


def pnum(num):
    assert num >= 0
    if num <= 9999:
        return "%d" % num
    num /= 1000.0
    if num <= 999:
        return "%.1fK" % num
    num /= 1000.0
    if num <= 999:
        return "%.1fM" % num
    num /= 1000.0
    if num <= 999:
        return "%.1fG" % num
    num /= 1000.0
    if num <= 999:
        return "%.1fT" % num
    num /= 1000.0
    if num <= 999:
        return "%.1fP" % num
    assert False

def pbyte(num):
    assert num >= 0
    if num <= 999:
        return "%d" % num
    num /= 1024.0
    if num <= 999:
        return "%.1fK" % num
    num /= 1024.0
    if num <= 999:
        return "%.1fM" % num
    num /= 1024.0
    if num <= 999:
        return "%.1fG" % num
    num /= 1024.0
    if num <= 999:
        return "%.1fT" % num
    num /= 1024.0
    if num <= 999:
        return "%.1fP" % num
    assert False


def pfloat(flt):
    assert flt >= 0
    if flt <= 999:
        return "%.1f" % flt
    return pnum(flt)


def ptime(secs):
    if not secs:
        return "None Yet"
    if secs < 2: # clear the jitter
        return "Just Now!"
    secs = int(secs)
    seconds = secs % 60
    secs //= 60
    mins = secs % 60
    secs //= 60
    hours = secs % 24
    days = secs  // 24
    if days > 0:
        return "%dd,%02dh" % (days, hours)
    if hours > 0:
        return "%2dh%02dm" % (hours, mins)
    return     "%2dm%02ds" % (mins, seconds)

def atime(secs):
    secs = int(secs)
    seconds = secs % 60
    secs //= 60
    mins = secs % 60
    secs //= 60
    hours = secs % 24
    days = secs  // 24
    if days > 0:
        return "%dd,%02dh" % (days, hours)
    return "%2dh%02dm" % (hours, mins)

class GuiDrawer:
    def __init__(self, workdir, stdscr):
        self.gui_mutex = Lock()
        self.workdir = workdir
        self.finished = False
        self.current_slave_id = 0
        self.stdscr = stdscr

        self.fix_rows = 22
        self.hex_rows = 12
        self.min_slave_rows = 4

        # Fenster und Hintergrundfarben
        curses.start_color()
        curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_BLACK)
        curses.init_pair(2, curses.COLOR_GREEN, curses.COLOR_BLACK)
        curses.init_pair(3, curses.COLOR_YELLOW, curses.COLOR_BLACK)
        curses.init_pair(4, curses.COLOR_RED, curses.COLOR_BLACK)
        default_col = curses.color_pair(1)
        self.stdscr.bkgd(default_col)
        self.stdscr.nodelay(True)

        self.gui = Interface(stdscr)
        self.data = GuiData(workdir)

        self.watcher = Thread(target=self.watch, args=(workdir,))
        self.watcher.daemon = True
        self.watcher.start()

        self.cpu_watcher = Thread(target=self.watch_cpu, args=())
        self.cpu_watcher.daemon = True
        self.cpu_watcher.start()


    def draw(self, cur_rows=None):
        d = self.data

        # size-limited display: try w/o hexdump, then limit slaves list
        cur_slave_rows = d.num_slaves()
        cur_hex_rows = self.hex_rows

        if cur_rows < self.fix_rows + self.hex_rows + d.num_slaves():
            cur_hex_rows = 0
            if cur_rows < self.fix_rows + d.num_slaves():
                cur_slave_rows = cur_rows - self.fix_rows

        assert(cur_slave_rows >= min(self.min_slave_rows, d.num_slaves()))

        self.gui.print_title_line("kAFL v0.2")
        self.gui.print_sep_line()
        self.gui.print_info_line([
            (16, "Runtime", ptime(d.runtime())),
            (16, "#Execs", pnum(d.total_execs())),
            (16, "Stability",  "%3d%%" % d.stability()),
            (16, "Slaves", "%d/%d" %
                (d.num_slaves(), d.cpu_cores()))])
        self.gui.print_info_line([
            (16, "", ""),
            (16, "CurExec/s", pnum(d.execs_p_sec_cur())),
            (16, "Funkiness", pfloat(d.relative_funky()) + "%"),
            #(16, "Reload/s", pnum(d.reload_p_sec()))])
            (16, "CPU Use", pnum(d.cpu_used()) + "%")])
            #(16, "", "")])
        self.gui.print_info_line([
            #(16, "", ""),
            (16, "User", pfloat(d.cpu_user()) + "%"),
            (16, "AvgExec/s", pnum(d.execs_p_sec_avg())),
            (16, "Timeouts", pfloat(d.relative_timeouts()) + "%"),
            (16, "Mem Use", pfloat(d.ram_used()) + "%")])
        self.gui.print_thin_line()
        self.gui.print_info_line([
            (16, "Path Info", ""),
            (16, "Bitmap Stats", ""),
            (36, "Findings", "")])
        self.gui.print_info_line([
            (16, " Total", pnum(d.paths_total())),
            (16, "", ""),
            (36, " Crash", "%6s (N/A) %10s" % (pnum((d.num_found("crash"))),
                                                 ptime(d.time_since("crash"))))])
        self.gui.print_info_line([
            (16, " Seeds", pnum(d.yield_imported())),
            (16, " Edges", pnum(d.bitmap_used())),
            (36, " AddSan", "%6s (N/A) %10s" % (pnum((d.num_found("kasan"))),
                                                 ptime(d.time_since("kasan"))))])
        self.gui.print_info_line([
            (16, " Favs", pnum(d.fav_total())),
            (16, " Blocks", pnum(d.bb_covered())),
            (36, " Timeout", "%6s (N/A) %10s" % (pnum((d.num_found("timeout"))),
                                                 ptime(d.time_since("timeout"))))])
        self.gui.print_info_line([
            (16, " Norm", pnum(d.normal_total())),
            (16, " p(col)", pfloat(d.p_coll()) + "%"),
            (36, " Regular", "%6s (N/A) %10s" % (pnum((d.num_found("regular"))),
                                                 ptime(d.time_since("regular"))))])
        self.gui.print_thin_line()
        self.gui.print_info_line([
            (11, "Init", pnum(d.yield_init())),
            (11, "Grim", pnum(d.yield_grim())),
            (11, "Redq", pnum(d.yield_redq()+d.yield_color())),
            (11, "Det", pnum(d.yield_det())),
            (11, "Hvc", pnum(d.yield_havoc()))
            ], prefix="Yld: ")
        self.gui.print_info_line([
            (11, "Init", pnum(d.fav_init())),
            (11, "Rq/Gr", pnum(d.fav_redq())),
            (11, "Det", pnum(d.fav_deter())),
            (11, "Hvc", pnum(d.fav_havoc())),
            (11, "Fin", pnum(d.fav_fin()))], prefix="Fav: ")
        self.gui.print_info_line([
            (11, "Init", pnum(d.normal_init())),
            (11, "Rq/Gr", pnum(d.normal_redq())),
            (11, "Det", pnum(d.normal_deter())),
            (11, "Hvc", pnum(d.normal_havoc())),
            (11, "Fin", pnum(d.normal_fin()))], prefix="Nrm: ")
        #self.gui.print_sep_line()
        self.gui.print_thin_line()
        slaves_start = min(d.num_slaves() - cur_slave_rows, self.current_slave_id)
        slaves_end   = min(d.num_slaves(), self.current_slave_id + cur_slave_rows)
        for i in range(slaves_start, slaves_end):
            hl = " "
            if i == self.current_slave_id:
                hl = ">"
            nid = d.slave_input_id(i)
            if d.slave_is_stalled(i):
                self.gui.print_info_line([(15, "", "[STALLED]"),
                                          (10, "node", "%5d" % d.slave_input_id(i)),
                                          (17, "fav/lvl", "        -"),
                                          (12, "exec/s",    "    -")],
                                          prefix="%c Slave %2d" % (hl, i))
            elif nid not in [None, 0] and d.nodes.get(nid, None):
                self.gui.print_info_line([(15, "", d.slave_stage(i)),
                                          (10, "node", "%5d" % d.slave_input_id(i)),
                                          (17, "fav/lvl",  "%5s/%3d" % (pnum(d.node_fav_bits(nid)),
                                                                        d.node_level(nid))),
                                          (12, "exec/s", pnum(d.slave_execs_p_sec(i)))],
                                          prefix="%c Slave %2d" % (hl, i))
            else:
                self.gui.print_info_line([(15, "", d.slave_stage(i)),
                                          (10, "node",       "    -"),
                                          (17, "fav/lvl", "        -"),
                                          (12, "exec/s",    "    -")],
                                          prefix="%c Slave %2d" % (hl, i))

        i = self.current_slave_id
        self.gui.print_thin_line()
        self.gui.print_title_line("Payload Info")
        self.gui.print_sep_line()
        nid = d.slave_input_id(i)
        if nid not in [None, 0] and d.nodes.get(nid, None):
            self.gui.print_info_line([
                (12, "Parent", "%5d" % d.node_parent_id(nid)),
                (11, "Size",   pbyte(d.node_size(nid)) + "B"),
                (13, "Perf",  "%.2fms" % (d.node_performance(nid)*1000)),
                (10, "Score",   pnum(d.node_score(nid))),
                (14, "Fuzzed",    atime(d.node_time(nid)))])
            self.gui.print_thin_line()
            if cur_hex_rows:
                self.gui.print_hexdump(d.node_payload(nid), max_rows=12)
                self.gui.print_thin_line()
        else:
            self.gui.print_info_line([
                (12, "Parent", "  N/A"),
                (12, "Size",   "  N/A"),
                (12, "Bytes",  "  N/A"),
                (12, "Bits",   "  N/A"),
                (12, "Exit",   " ")])
            self.gui.print_thin_line()
            if cur_hex_rows:
                self.gui.print_hexdump(b"importing...", max_rows=12)
                self.gui.print_thin_line()
        #self.gui.print_title_line("Log")
        self.gui.refresh()

    def loop(self):
        self.gui.refresh()
        while True:
            redraw = False
            char = self.stdscr.getch()
            if char == curses.KEY_UP:
                self.current_slave_id = (self.current_slave_id - 1) % self.data.num_slaves()
                redraw = True
            elif char == curses.KEY_DOWN:
                self.current_slave_id = (self.current_slave_id + 1) % self.data.num_slaves()
                redraw = True
            elif char == ord("q") or char == ord("Q"):
                self.finished = True
                return

            if not redraw and not self.data.redraw:
                time.sleep(0.1)

            self.gui_mutex.acquire()

            #self.gui.clear()
            self.gui.refresh()
            min_rows = self.fix_rows + self.min_slave_rows
            min_cols = 82
            cur_rows, cur_cols = self.stdscr.getmaxyx()

            try:
                self.draw(cur_rows)
            except:
                if cur_cols < min_cols or cur_rows < min_rows:
                    print("Terminal too small? (found: %dx%d)" % (cur_rows, cur_cols));
                    self.gui.refresh()
                else:
                    raise
            finally:
                self.data.redraw = False
                self.gui_mutex.release()

    def watch(self, workdir):
        d = self.data
        mask = (inotify.constants.IN_MOVED_TO)
        self.inotify = inotify.adapters.Inotify()
        i = self.inotify
        i.add_watch(workdir, mask)
        i.add_watch(workdir + "/metadata/", mask)

        for event in i.event_gen(yield_nones=False):
            if self.finished:
                return
            self.gui_mutex.acquire()
            try:
                (_, type_names, path, filename) = event
                d.update(path, filename)
                d.redraw = True
            finally:
                self.gui_mutex.release()

    def watch_cpu(self):
        while True:
            if self.finished:
                return
            cpu_info = psutil.cpu_times_percent(interval=2, percpu=False)
            mem_info = psutil.virtual_memory()
            swap_info = psutil.swap_memory()
            self.gui_mutex.acquire()
            try:
                self.data.mem = mem_info
                self.data.cpu = cpu_info
                self.data.swap = swap_info
                self.data.redraw = True
            finally:
                self.gui_mutex.release()


class GuiData:

    def __init__(self, workdir):
        self.workdir = workdir
        self.slave_stats = list()
        self.load_initial()
        self.redraw = True

    def load_initial(self):
        self.cpu = psutil.cpu_times_percent(interval=0.01, percpu=False)
        self.mem = psutil.virtual_memory()
        self.cores_phys = psutil.cpu_count(logical=False)
        self.cores_virt = psutil.cpu_count(logical=True)
        self.stats = self.read_file("stats")

        try:
            self.config = self.read_file("config")
            if not self.config:
                raise FileNotFoundError("$workdir/config")
            self.bitmap_size = self.config['BITMAP_SHM_SIZE']
        except Exception:
            # legacy fallback
            self.bitmap_size = 64*1024

        if not self.stats:
            raise FileNotFoundError("$workdir/stats")


        print("Waiting for slaves to launch..")
        num_slaves = self.stats.get("num_slaves",0)
        init_data = None
        for slave_id in range(0, num_slaves):
            while init_data is None:
                time.sleep(0.1)
                init_data = self.read_file("slave_stats_%d" % slave_id)
            self.slave_stats.append(init_data)

        # TODO frontend is using time.time() when we actually need time.clock(), plus perhaps the startup time/date
        self.starttime = min([x["start_time"] for x in self.slave_stats])

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
            "exit_reasons": {"regular": 0, "crash": 0, "kasan": 0, "timeout": 0},
            "last_found": {"regular": 0, "crash": 0, "kasan": 0, "timeout": 0}
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

            last_found = self.aggregated["last_found"][node["info"]["exit_reason"]]
            this_found = node["info"]["time"]
            if last_found < this_found:
                self.aggregated["last_found"][node["info"]["exit_reason"]] = this_found


    def runtime(self):
        return max([x["run_time"] for x in self.slave_stats])

    def execs_p_sec_cur(self):
        return sum([x.get("execs/sec",0) for x in self.slave_stats])

    def execs_p_sec_avg(self):
        return self.total_execs()/self.runtime()

    def total_execs(self):
        # avoid div-by-zero
        return self.stats.get("total_execs")

    def num_slaves(self):
        return len(self.slave_stats)

    def num_found(self, reason):
        return self.aggregated["exit_reasons"][reason]

    def time_since(self, reason):
        time_stamp = self.aggregated["last_found"][reason]
        if not time_stamp:
            return None
        return self.starttime + self.runtime() - time_stamp

    def pending_fav(self):
        if self.fav_total() > 0:
            return 100 * (self.fav_total() - self.fav_fin()) / float(self.fav_total())
        return 0

    def stability(self):
        try:
            # chance p() to survive 100 executions: ((total-crashes)/total)^100
            n = self.total_execs()
            c = self.total_reloads()
            return 100*((n-c)/n)**100
        except ZeroDivisionError:
            return 0

    def total_reloads(self):
        return self.stats.get("num_reload", 0)

    def total_timeouts(self):
        return self.stats.get("num_timeout", 0)

    def relative_timeouts(self):
        try:
            return 100.0*self.total_timeouts()/self.total_execs()
        except:
            return 0

    def total_funky(self):
        return self.stats.get("num_funky", 0)

    def relative_funky(self):
        try:
            return self.total_funky()/self.total_execs()
        except ZeroDivisionError:
            return 0

    def reload_p_sec(self):
        return self.total_reloads()/self.runtime()

    def cycles(self):
        return self.stats.get("cycles", 0)

    def cpu_total(self):
        return "%d(%d)" % (self.cores_phys, self.cores_virt)

    def cpu_cores(self):
        return self.cores_phys

    def cpu_used(self):
        return self.cpu.user + self.cpu.system

    def cpu_user(self):
        # ignore occasional negatives..
        return max(0, self.cpu.user - self.cpu.guest)

    def cpu_vm(self):
        return self.cpu.guest

    def ram_total(self):
        return self.mem.total

    def ram_avail(self):
        return self.mem.available

    def ram_used(self):
        return 100 * float(self.mem.used) / float(self.mem.total)

    def swap_used(self):
        return self.swap.used

    def yield_imported(self):
        return self.stats["yield"].get("import", 0)

    def yield_init(self):
        return (self.stats["yield"].get("trim", 0) +
                self.stats["yield"].get("trim_funky", 0) +
                self.stats["yield"].get("center_trim", 0) +
                self.stats["yield"].get("center_trim_funky", 0) +
                self.stats["yield"].get("calibrate", 0))

    def yield_grim(self):
        return (self.stats["yield"].get("grim_inference", 0) +
                self.stats["yield"].get("grim_generalize", 0) +
                self.stats["yield"].get("grim_recursive", 0) +
                self.stats["yield"].get("grim_extension", 0) +
                self.stats["yield"].get("grim_repl_str", 0))

    def yield_redq(self):
        return (self.stats["yield"].get("redq_mutate", 0) +
                self.stats["yield"].get("redq_dict", 0))

    def yield_color(self):
        return self.stats["yield"].get("redq_coloring", 0)

    def yield_havoc(self):
        return (self.stats["yield"].get("afl_havoc", 0) +
                self.stats["yield"].get("afl_splice", 0) +
                self.stats["yield"].get("radamsa", 0))

    def yield_det(self):
        return (self.stats["yield"].get("afl_arith_1", 0) +
                self.stats["yield"].get("afl_arith_2", 0) +
                self.stats["yield"].get("afl_arith_4", 0) +
                self.stats["yield"].get("afl_flip_1/1", 0) +
                self.stats["yield"].get("afl_flip_2/1", 0) +
                self.stats["yield"].get("afl_flip_4/1", 0) +
                self.stats["yield"].get("afl_flip_8/1", 0) +
                self.stats["yield"].get("afl_flip_8/2", 0) +
                self.stats["yield"].get("afl_flip_8/4", 0) +
                self.stats["yield"].get("afl_int_1", 0) +
                self.stats["yield"].get("afl_int_2", 0) +
                self.stats["yield"].get("afl_int_4", 0))


    def normal_total(self):
        return (self.normal_init() + self.normal_redq() + self.normal_deter() +
                self.normal_havoc() + self.normal_fin())

    def normal_init(self):
        return self.aggregated["normal_states"].get("initial", 0)

    def normal_redq(self):
        return self.aggregated["normal_states"].get("redq/grim", 0)

    def normal_deter(self):
        return self.aggregated["normal_states"].get("deterministic", 0)

    def normal_havoc(self):
        return self.aggregated["normal_states"].get("havoc", 0)
        return 0

    def normal_fin(self):
        return self.aggregated["normal_states"].get("final", 0)

    def fav_total(self):
        return (self.fav_init() + self.fav_redq() +
                self.fav_deter() + self.fav_havoc() + self.fav_fin())

    def fav_init(self):
        return self.aggregated["fav_states"].get("initial", 0)

    def fav_redq(self):
        return self.aggregated["fav_states"].get("redq/grim", 0)

    def fav_deter(self):
        return self.aggregated["fav_states"].get("deterministic", 0)

    def fav_havoc(self):
        return self.aggregated["fav_states"].get("havoc", 0)

    def fav_fin(self):
        return self.aggregated["fav_states"].get("final", 0)

    def bitmap_used(self):
        return self.stats["bytes_in_bitmap"]

    def bb_covered(self):
        return self.stats["max_bb_cov"]

    def paths_total(self):
        return self.stats["paths_total"]

    def p_coll(self):
        return 100.0 * float(self.bitmap_used()) / self.bitmap_size


    def slave_stage(self, i):
        method = self.slave_stats[i].get("method", None)
        stage  = self.slave_stats[i].get("stage", "[waiting..]")
        if method:
            #return "%s/%s" % (stage[0:6],method[0:12])
            return "%s" % method[0:14]
        else:
            return stage[0:14]

    def slave_execs_p_sec(self, i):
        return self.slave_stats[i].get("execs/sec")

    def slave_total_execs(self, i):
        return self.slave_stats[i].get("total_execs")

    def slave_input_id(self, i):
        return self.slave_stats[i]["node_id"]

    def slave_is_stalled(self, i):
        return (self.runtime() - self.slave_stats[i]["run_time"]) > 10

    def node_size(self, nid):
        return self.nodes[nid]["payload_len"]

    def node_performance(self, nid):
        return self.nodes[nid]["performance"]

    def node_score(self, nid):
        return self.nodes[nid]["fav_factor"]

    def node_time(self, nid):
        return self.nodes[nid]["attention_secs"]

    def node_level(self, nid):
        return self.nodes[nid].get("level", 0)

    def node_parent_id(self, nid):
        return self.nodes[nid]["info"]["parent"]

    def node_fav_bits(self, nid):
        if not self.nodes.get(nid, None):
            return -1
        favs = self.nodes[nid].get("fav_bits", None)
        if favs:
            return len(favs)
        else:
            return 0

    def node_new_bytes(self, nid):
        return len(self.nodes[nid]["new_bytes"])

    def node_new_bits(self, nid):
        return len(self.nodes[nid]["new_bits"])

    def node_exit_reason(self, nid):
        return self.nodes[nid]["info"]["exit_reason"][0]

    def node_payload(self, nid):
        exit_reason = self.nodes[nid]["info"]["exit_reason"]
        filename = self.workdir + "/corpus/%s/payload_%05d" % (exit_reason, nid)
        return read_binary_file(filename)[0:1024]  # TODO remove path traversal vuln

    def load_slave(self, id):
        self.slave_stats[id] = self.read_file("slave_stats_%d" % id)

    def load_global(self):
        self.stats = self.read_file("stats")

    def update(self, pathname, filename):
        if "node_" in filename:
            self.load_node(pathname + "/" + filename)
            self.aggregate()
        elif "slave_stats" in filename:
            for i in range(0, self.num_slaves()):
                self.load_slave(i)
        elif filename == "stats":
            self.load_global()

    def read_file(self, name):
        retry = 4
        data = None
        while retry > 0:
            try:
                data = read_binary_file(self.workdir + "/" + name)
                break
            except:
                retry -= 1
        if data:
            return msgpack.unpackb(data, raw=False, strict_map_key=False)
        else:
            return None


def main(stdscr):
    gui = GuiDrawer(sys.argv[1], stdscr)
    gui.loop()

if __name__ == "__main__":

    locale.setlocale(locale.LC_ALL, '')
    code = locale.getpreferredencoding()

    if len(sys.argv) < 2 or not os.path.exists(sys.argv[1]):
        print("Usage: " + sys.argv[0] + " <kafl-workdir>")
        sys.exit(1)

    try:
        curses.wrapper(main)
    except FileNotFoundError as e:
        # ignore - typically just a fuzzer restart or wrong argv[1]
        print("Error reading from workdir. Exit.")
