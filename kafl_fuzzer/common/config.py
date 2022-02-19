# Copyright 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

import argparse
import os
import re
import sys

import confuse
from flatdict import FlatDict

from kafl_fuzzer.common.util import is_float, is_int, Singleton
from kafl_fuzzer.common.logger import logger


class ArgsParser(argparse.ArgumentParser):
    def error(self, message):
        self.print_help()
        logger.error("%s\n" % message)
        sys.exit(1)


class FullPath(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace, self.dest, os.path.abspath(os.path.expanduser(values)))


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
    parser.add_argument('-p', '--workers', required=False, metavar='<num>', type=int, default=1,
                        help='number of workers (Qemu instances)')
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
    parser.add_argument('-D', '--afl-no-deterministic', required=False, help='skip deterministic stage (dumb mode).',
                        action='store_true', default=False)
    parser.add_argument('--afl-no-effector', required=False, help='disable effector maps during deterministic stage.',
                        action='store_true', default=False)
    parser.add_argument('--afl-skip-zero', required=False, help='skip zero bytes during deterministic stage.',
                        action='store_true', default=False)
    parser.add_argument('-i', '--afl-skip-range', required=False, type=parse_ignore_range, metavar="[0-131072]", action='append',
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
    parser.add_argument('-ts', '--timeout_soft', required=False, metavar='<s>', help="soft timeout for Qemu execution (in seconds)",
                        type=float, default=1/1000)
    parser.add_argument('-tc', '--timeout_check', required=False, help="enable timeout validation (can be slow)",
                        action='store_true', default=False)
    parser.add_argument('--kickstart', metavar='<n>', help="kickstart fuzzing with size <n> random strings (default 256, 0 to disable)",
                        type=int, required=False, default=256)

    parser.add_argument('--afl-arith-max', metavar='<n>', help="max arithmetic range for afl_arith_n mutation",
                        type=int, required=False, default=35)
    parser.add_argument('--radamsa-path', metavar='<file>', help="path to radamsa executable",
                        type=parse_is_file, required=False, default=None)

# Qemu/Worker-specific launch options
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
    parser.add_argument('-t', '--timeout_hard', required=False, metavar='<s>', help="hard timeout for Qemu executions (seconds)",
                        type=float, default=4)

    parser.add_argument('--payload-shm-size', metavar='<n>', help="maximum payload size in bytes",
                        type=int, required=False, default=131072)
    parser.add_argument('--bitmap-size', metavar='<n>', help="size of feedback bitmap (power of 2)",
                        type=int, required=False, default=65536)
    parser.add_argument('--qemu-path', metavar='<file>', help=argparse.SUPPRESS,
                        type=parse_is_file, required=True, default=None)

# kafl_debug launch options
def add_args_debug(parser):

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
    
    parser.add_argument('-input', metavar='<file/dir>', action=FullPath, type=str,
                        help='path to input file or workdir.')
    parser.add_argument('-n', '--iterations', metavar='<n>', help='execute <n> times (for some actions)',
                        default=5, type=int)
    
    parser.add_argument('-trace', required=False, help='capture full PT traces (for some actions)',
                    action='store_true', default=False)
    parser.add_argument('-action', required=False, metavar='<cmd>', choices=debug_modes,
                        help=debug_modes_help)
    parser.add_argument('--ptdump-path', metavar='<file>', help=argparse.SUPPRESS,
                        type=parse_is_file, required=True, default=None)


class ConfigArgsParser():

    def _base_parser(self):
        return ArgsParser(formatter_class=argparse.RawTextHelpFormatter, add_help=False)

    def _parse_with_config(self, parser):

        config = confuse.Configuration('kafl', modname='kafl_fuzzer')

        # check default config search paths
        config.read(defaults=True, user=True)

        # local / workdir config
        workdir_config = os.path.join(os.getcwd(), 'kafl.yaml')
        if os.path.exists(workdir_config):
            config.set_file(workdir_config, base_for_paths=True)

        # ENV based config
        if 'KAFL_CONFIG' in os.environ:
            config.set_file(os.environ['KAFL_CONFIG'], base_for_paths=True)

        # merge all configs into a flat dictionary, delimiter = ':'
        config_values = FlatDict(config.flatten())
        #print("Options picked up from config: %s" % str(config_values))

        # adopt defaults into parser, fixup 'required' and file/path fields
        for action in parser._actions:
            #print("action: %s" % repr(action))
            if action.dest in config_values:
                if action.type == parse_is_file:
                    action.default = config[action.dest].as_filename()
                action.required = False
                config_values.pop(action.dest)
        
        # remove options not defined in argparse (set_defaults() imports everything)
        for option in config_values:
            if 'KAFL_CONFIG_DEBUG' in os.environ:
                parser.warn("Unrecognized config option '%s'." % option)
                sys.exit(-1)
            config_values.pop(option)

        parser.set_defaults(**config_values)
        args = parser.parse_args()
        #print("args: %s" % repr(args))
        #sys.exit(-1)
        return args

    def parse_fuzz_options(self):

        parser = self._base_parser()

        general = parser.add_argument_group('General options')
        add_args_general(general)

        fuzzer = parser.add_argument_group('Fuzzer options')
        add_args_fuzzer(fuzzer)

        qemu = parser.add_argument_group('Qemu options')
        add_args_qemu(qemu)

        return self._parse_with_config(parser)

    def parse_debug_options(self):

        parser = self._base_parser()

        general = parser.add_argument_group('General options')
        add_args_general(general)

        debugger = parser.add_argument_group('Debug options')
        add_args_debug(debugger)

        qemu = parser.add_argument_group('Qemu options')
        add_args_qemu(qemu)

        return self._parse_with_config(parser)
