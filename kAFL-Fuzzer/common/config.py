# Copyright 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

import argparse
import json
import os
import re
import sys

import six.moves.configparser

from dateutil.parser import parse as dateparser
from common.util import is_float, is_int, Singleton
from common.log import logger
import six


default_section = "Fuzzer"
default_config = {"PAYLOAD_SHM_SIZE": 131072,
                  "BITMAP_SHM_SIZE": 65536,
                  "QEMU_KAFL_LOCATION": "",
                  "RADAMSA_LOCATION": "radamsa/bin/radamsa",
                  "ARITHMETIC_MAX": 35,
                  "APPLE-SMC-OSK": "",
                  }


class ArgsParser(argparse.ArgumentParser):
    def error(self, message):
        self.print_help()
        logger.warn('%s\n\n' % message)
        sys.exit(1)


def create_dir(dirname):
    if not os.path.isdir(dirname):
        try:
            os.makedirs(dirname)
        except:
            msg = "Cannot create directory: {0}".format(dirname)
            raise argparse.ArgumentTypeError(msg)
    return dirname


def parse_is_dir(dirname):
    if not os.path.isdir(dirname):
        msg = "{0} is not a directory".format(dirname)
        raise argparse.ArgumentTypeError(msg)
    else:
        return dirname


def parse_is_file(dirname):
    if not os.path.isfile(dirname):
        msg = "{0} is not a file".format(dirname)
        raise argparse.ArgumentTypeError(msg)
    else:
        return dirname


def parse_ignore_range(string):
    m = re.match(r"(\d+)(?:-(\d+))?$", string)
    if not m:
        raise argparse.ArgumentTypeError("'" + string + "' is not a range of number.")
    start = min(int(m.group(1)), int(m.group(2)))
    end = max(int(m.group(1)), int(m.group(2))) or start
    if end > (128 << 10):
        raise argparse.ArgumentTypeError("Value out of range (max 128KB).")

    if start == 0 and end == (128 << 10):
        raise argparse.ArgumentTypeError("Invalid range specified.")
    return list([start, end])


def parse_range_ip_filter(string):
    m = re.match(r"([(0-9abcdef]{1,16})(?:-([0-9abcdef]{1,16}))?$", string.replace("0x", "").lower())
    if not m:
        raise argparse.ArgumentTypeError("'" + string + "' is not a range of number.")

    # print(m.group(1))
    # print(m.group(2))
    start = min(int(m.group(1).replace("0x", ""), 16), int(m.group(2).replace("0x", ""), 16))
    end = max(int(m.group(1).replace("0x", ""), 16), int(m.group(2).replace("0x", ""), 16)) or start

    if start > end:
        raise argparse.ArgumentTypeError("Invalid range specified.")
    return list([start, end])

# General startup options used by fuzzer, qemu, and/or utilities
def add_args_general(parser):
    parser.add_argument('-h', '--help', action='help',
                        help='show this help message and exit')
    parser.add_argument('-work_dir', metavar='<dir>', action=FullPath, type=str,
                        required=True, help='path to the output/working directory.')
    parser.add_argument('--purge', required=False, help='purge the working directory at startup.',
                        action='store_true', default=False)
    parser.add_argument('--resume', required=False, help='use VM snapshot from existing workdir (for cov/gdb)',
                        action='store_true', default=False)
    parser.add_argument('-p', required=False, metavar='<num>', type=int, default=1,
                        help='number of parallel Qemu instances.')
    parser.add_argument('-v', '--verbose', required=False, action='store_true', default=False,
                        help='use verbose console output')
    parser.add_argument('-q', '--quiet', help='only print warnings and errors to console',
                        required=False, action='store_true', default=False)
    parser.add_argument('-l', '--log', help='enable standard logging to $workdir/debug.log',
                        action='store_true', default=False)
    parser.add_argument('--debug', help='enable extra debug checks and max logging verbosity',
                        action='store_true', default=False)

# kAFL/Fuzzer-specific options
def add_args_fuzzer(parser):
    parser.add_argument('-seed_dir', required=False, metavar='<dir>', action=FullPath,
                        type=parse_is_dir, help='path to the seed directory.')
    parser.add_argument('-dict', required=False, metavar='<file>', type=parse_is_file,
                        help='import dictionary file for use in havoc stage.', default=None)
    parser.add_argument('-trace', required=False, help='store new traces while fuzzing.',
                        action='store_true', default=False)
    parser.add_argument('-funky', required=False, help='perform extra validation and store funky inputs.',
                        action='store_true', default=False)
    parser.add_argument('-D', required=False, help='skip deterministic stage (dumb mode).',
                        action='store_false', default=True)
    parser.add_argument('-d', required=False, help='disable effector maps during deterministic stage.',
                        action='store_false', default=True)
    parser.add_argument('-s', required=False, help='skip zero bytes during deterministic stage.',
                        action='store_true', default=False)
    parser.add_argument('-i', required=False, type=parse_ignore_range, metavar="[0-131072]", action='append',
                        help='skip byte range during deterministic stage (0-128KB).')
    parser.add_argument('-radamsa', required=False, help='enable Radamsa as additional havoc stage',
                        action='store_true', default=False)
    parser.add_argument('-grimoire', required=False, help='enable Grimoire analysis & mutation stages',
                        action='store_true', default=False)
    parser.add_argument('-redqueen', required=False, help='enable Redqueen trace & insertion stages',
                        action='store_true', default=False)
    parser.add_argument('-fix_hashes', required=False, help='enable Redqueen checksum fixer (broken)',
                        action='store_true', default=False)
    parser.add_argument('-hammer_jmp_tables', required=False, help='enable Redqueen jump table hammering (?)',
                        action='store_true', default=False)
    parser.add_argument('-redq_do_simple', required=False, help='do not ignore simple arith. matches in Redqueen',
                        action='store_true', default=False)
    parser.add_argument('-cpu_offset', metavar='<n>', help="offset CPU pinning to start at <N>",
                        type=int, default=0, required=False)
    parser.add_argument('-abort_time', metavar='<n>', help="exit after n hours",
                        type=float, required=False, default=None)
    parser.add_argument('-abort_exec', metavar='<n>', help="exit after max executions",
                        type=int, required=False, default=None)
    parser.add_argument('-ts', '--t_soft', required=False, metavar='<s>', help="soft timeout for Qemu execution (in seconds)",
                        type=float, default=1/1000)
    parser.add_argument('-tc', '--t_check', required=False, help="enable timeout validation (can be slow)",
                        action='store_true', default=False)
    parser.add_argument('--kickstart', metavar='<n>', help="kickstart fuzzing with size <n> random strings (default 256, 0 to disable)",
                        type=int, required=False, default=256)

# Qemu/Slave-specific launch options
def add_args_qemu(parser):

    # BIOS/VM/Kernel load modes are exclusive, but we need at least one of them
    xorarg = parser.add_mutually_exclusive_group(required=True)

    xorarg.add_argument('-vm_image', metavar='<QCow2 File>', required=False, action=FullPath, 
                        type=parse_is_file, help='path to the VM\'s disk image.')
    parser.add_argument('-sharedir', metavar='<dir>', required=False, action=FullPath,
                        type=parse_is_dir, help='path to the page buffer share directory.')
    xorarg.add_argument('-vm_snapshot', metavar='<dir>', required=False, action=FullPath,
                        type=parse_is_dir, help='path to the VM\'s pre-snapshot directory.')

    xorarg.add_argument('-kernel', metavar='<file>', required=False, action=FullPath, type=parse_is_file,
                        help='path to the Kernel image.')
    parser.add_argument('-initrd', metavar='<file>', required=False, action=FullPath, type=parse_is_file,
                        help='path to the initrd/initramfs file.')

    xorarg.add_argument('-bios', metavar='<file>', required=False, action=FullPath, type=parse_is_file,
                        help='path to the BIOS image.')

    parser.add_argument('-mem', metavar='<num>', help='size of virtual memory in MB (default: 256).',
                        default=256, type=int)

    parser.add_argument('-ip0', required=False, default=None, metavar='<start-end>', type=parse_range_ip_filter,
                        help='set IP trace filter range 0 (must be page-aligned!)')
    parser.add_argument('-ip1', required=False, default=None, metavar='<start-end>', type=parse_range_ip_filter,
                        help='Set IP trace filter range 1 (must be page-aligned!)')
    parser.add_argument('-ip2', required=False, default=None, metavar='<start-end>', type=parse_range_ip_filter,
                        help='Set IP trace filter range 2 (must be page-aligned!)')
    parser.add_argument('-ip3', required=False, default=None, metavar='<start-end>', type=parse_range_ip_filter,
                        help='Set IP trace filter range 3 (must be page-aligned!)')

    parser.add_argument('-macOS', required=False, help='enable macOS mode (requires Apple OSK)',
                        action='store_true', default=False)
    parser.add_argument('-extra', metavar='<args>', required=False, help='extra arguments to add to qemu cmdline',
                        default="", type=str)
    parser.add_argument('-X', metavar='<type>', required=False, help='launch Qemu with -display <type>, e.g. vnc',
                        type=str, default=False)
    parser.add_argument("-trace_cb", required=False, help='enable tracing based on libxdc edge callback',
                        action='store_true', default=False)

    parser.add_argument('-forkserver', required=False, help='target has forkserver (skip Qemu resets)',
                        action='store_true', default=False)
    parser.add_argument('-R', '--no_fast_reload', required=False, help='disable fast reload mode',
                        action='store_true', default=False)
    parser.add_argument('-catch_resets', required=False, help='interpret silent VM reboot as KASAN events',
                        action='store_true', default=False)
    parser.add_argument('-gdbserver', required=False, help='enable Qemu gdbserver (use via kafl_debug.py!)',
                        action='store_true', default=False)
    parser.add_argument('--log_hprintf', required=False, help="log hprintf output to seperate files (not console)",
                        action='store_true', default=False)
    parser.add_argument('--log_crashes', required=False, help="store hprintf log on crash/timeout (not console, not logs)",
                        action='store_true', default=False)
    parser.add_argument('-t', '--timeout', required=False, metavar='<s>', help="hard timeout for Qemu executions (seconds)",
                        type=float, default=4)


class FullPath(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace, self.dest, os.path.abspath(os.path.expanduser(values)))


class MapFullPaths(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace, self.dest, [os.path.abspath(os.path.expanduser(p)) for p in values])


class ConfigReader(object):

    def __init__(self, config_file, section, default_values):
        self.section = section
        self.default_values = default_values
        self.config = six.moves.configparser.ConfigParser()
        if config_file:
            self.config.read(config_file)
        self.config_value = {}
        self.__set_config_values()

    def __set_config_values(self):
        for default_value in self.default_values.keys():
            if self.config.has_option(self.section, default_value):
                try:
                    self.config_value[default_value] = int(self.config.get(self.section, default_value))
                except ValueError:
                    if self.config.get(self.section, default_value) == "True":
                        self.config_value[default_value] = True
                    elif self.config.get(self.section, default_value) == "False":
                        self.config_value[default_value] = False
                    elif self.config.get(self.section, default_value).startswith("[") and \
                            self.config.get(self.section, default_value).endswith("]"):
                        self.config_value[default_value] = \
                            self.config.get(self.section, default_value)[1:-1].replace(' ', '').split(',')
                    elif self.config.get(self.section, default_value).startswith("{") and \
                            self.config.get(self.section, default_value).endswith("}"):
                        self.config_value[default_value] = json.loads(self.config.get(self.section, default_value))
                    else:
                        if is_float(self.config.get(self.section, default_value)):
                            self.config_value[default_value] = float(self.config.get(self.section, default_value))
                        elif is_int(self.config.get(self.section, default_value)):
                            self.config_value[default_value] = int(self.config.get(self.section, default_value))
                        else:
                            self.config_value[default_value] = self.config.get(self.section, default_value)
            else:
                self.config_value[default_value] = self.default_values[default_value]

    def get_values(self):
        return self.config_value



class DebugConfiguration(six.with_metaclass(Singleton)):
    global default_section, default_config

    __config_section = default_section
    __config_default = default_config

    def __init__(self, configfile, initial=True):
        self.config_file = configfile
        if initial:
            self.argument_values = None
            self.config_values = None
            self.__load_arguments()
            self.__load_config()
            self.load_old_state = False

    def __load_config(self):
        self.config_values = ConfigReader(self.config_file, self.__config_section,
                                          self.__config_default).get_values()

    def __load_arguments(self):

        debug_modes = ["benchmark", "gdb", "trace", "single", "trace-qemu", "noise", "printk", "redqueen",
                       "redqueen-qemu", "verify"]

        debug_modes_help = '<benchmark>\tperform performance benchmark\n' \
                           '<gdb>\t\trun payload with Qemu gdbserver (must compile without redqueen!)\n' \
                           '<trace>\t\tperform trace run\n' \
                           '<trace-qemu>\tperform trace run and print QEMU stdout\n' \
                           '<noise>\t\tperform run and messure nondeterminism\n' \
                           '<printk>\t\tredirect printk calls to kAFL\n' \
                           '<redqueen>\trun redqueen debugger\n' \
                           '<redqueen-qemu>\trun redqueen debugger and print QEMU stdout\n' \
                           '<verify>\t\trun verifcation steps\n'

        parser = ArgsParser(formatter_class=argparse.RawTextHelpFormatter, add_help=False)

        general = parser.add_argument_group('General options')
        add_args_general(general)

        general.add_argument('-input', metavar='<file/dir>', action=FullPath, type=str,
                            help='path to input file or workdir.')
        general.add_argument('-n', metavar='<num>', help='execute <num> times (for some actions)',
                            default=5, type=int)
        parser.add_argument('-trace', required=False, help='capture full PT traces (for some actions)',
                        action='store_true', default=False)
        general.add_argument('-action', required=False, metavar='<cmd>', choices=debug_modes,
                            help=debug_modes_help)

        qemu = parser.add_argument_group('Qemu options')
        add_args_qemu(qemu)

        self.argument_values = vars(parser.parse_args())


class FuzzerConfiguration(six.with_metaclass(Singleton)):
    global default_section, default_config

    __config_section = default_section
    __config_default = default_config

    def __init__(self, configfile, emulated_arguments=None, skip_args=False):
        self.config_file = configfile
        if not emulated_arguments:
            self.argument_values = None
            self.config_values = None
            if not skip_args:
                self.__load_arguments()
            self.__load_config()
            self.load_old_state = False
        else:
            self.argument_values = emulated_arguments
            self.__load_config()
            self.load_old_state = False

    def create_initial_config(self):
        f = open(self.config_file, "w")
        config = six.moves.configparser.ConfigParser()
        config.add_section(self.__config_section)
        for k, v in self.__config_default.items():
            if v is None or (type(v) is str and v == ""):
                config.set(self.__config_section, k, "\"\"")
            else:
                config.set(self.__config_section, k, v)
        config.write(f)
        f.close()

    def __load_config(self):
        self.config_values = ConfigReader(self.config_file, self.__config_section,
                                          self.__config_default).get_values()

    def __load_arguments(self):

        parser = ArgsParser(formatter_class=argparse.RawTextHelpFormatter, add_help=False)

        general = parser.add_argument_group('General options')
        add_args_general(general)

        fuzzer = parser.add_argument_group('Fuzzer options')
        add_args_fuzzer(fuzzer)

        qemu = parser.add_argument_group('Qemu options')
        add_args_qemu(qemu)

        self.argument_values = vars(parser.parse_args())
