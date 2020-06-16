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

import argparse
import json
import os
import re
import sys

import ConfigParser

from common.util import is_float, is_int, json_dumper, Singleton

default_section = "Fuzzer"
default_config = {"UI_REFRESH_RATE": 0.25,
                  "MASTER_SHM_PREFIX": "kafl_master_",
                  "MAPSERV_SHM_PREFIX": "kafl_mapserver_",
                  "BITMAP_SHM_PREFIX": "kafl_bitmap_",
                  "PAYLOAD_SHM_SIZE": (65 << 10),
                  "BITMAP_SHM_SIZE": (64 << 10),
                  "QEMU_KAFL_LOCATION": None,
                  "ABORTION_TRESHOLD": 500,
                  "TIMEOUT_TICK_FACTOR": 10.0,
                  "ARITHMETIC_MAX": 35,
                  "APPLE-SMC-OSK": "",
                  "DEPTH-FIRST-SEARCH": False,
                  "AGENTS-FOLDER": "./../Target-Components/agents/",
                  "MAX_MIN_BUCKETS": False
                  }


class ArgsParser(argparse.ArgumentParser):
    def error(self, message):
        self.print_help()
        print('\033[91m[Error] %s\n\n\033[0m\n' % message)
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


class FullPath(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace, self.dest, os.path.abspath(os.path.expanduser(values)))


class MapFullPaths(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace, self.dest, map(lambda p: os.path.abspath(os.path.expanduser(p)), values))


class ConfigReader(object):

    def __init__(self, config_file, section, default_values):
        self.section = section
        self.default_values = default_values
        self.config = ConfigParser.ConfigParser()
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


class VizConfiguration:
    __metaclass__ = Singleton

    def __init__(self, initial=True):
        if initial:
            self.argument_values = None
            self.config_values = None
            self.__load_arguments()
            self.load_old_state = False

    def __load_arguments(self):
        parser = ArgsParser(formatter_class=argparse.RawTextHelpFormatter)

        viz_modes = ["dot", "plot"]
        viz_modes_help = '<dot>\tvisulize kafl fuzzer tree\n' \
                         '<plot>\t\tplot performance and runtime data\n'

        parser.add_argument('work_dir', metavar='<Working Directory>', action=FullPath, type=create_dir,
                            help='Path to the working directory.')

        parser.add_argument('mode', metavar='<Mode>', choices=viz_modes, help=viz_modes_help)

        self.argument_values = vars(parser.parse_args())


class UserPrepareConfiguration:
    __metaclass__ = Singleton
    global default_section, default_config

    __config_section = default_section
    __config_default = default_config

    def __init__(self, initial=True):
        if initial:
            self.argument_values = None
            self.config_values = None
            self.__load_arguments()
            self.__load_config()
            self.load_old_state = False

    def __load_config(self):
        self.config_values = ConfigReader(os.path.dirname(sys.argv[0]) + "/kafl.ini", self.__config_section,
                                          self.__config_default).get_values()

    def __load_arguments(self):
        modes = ["m32", "m64"]
        modes_help = 'm32\tpack and compile as an i386   executable.\n' \
                     'm64\tpack and compile as an x86-64 executable.\n'

        parser = ArgsParser(formatter_class=argparse.RawTextHelpFormatter)

        parser.add_argument('binary_file', metavar='<Executable>', action=FullPath, type=parse_is_file,
                            help='path to the user space executable file.')
        parser.add_argument('output_dir', metavar='<Output Directory>', action=FullPath, type=parse_is_dir,
                            help='path to the output directory.')
        parser.add_argument('mode', metavar='<Mode>', choices=modes, help=modes_help)
        parser.add_argument('-args', metavar='<args>', help='define target arguments.', default="", type=str)
        parser.add_argument('-file', metavar='<file>', help='write payload to file instead of stdin.', default="",
                            type=str)
        parser.add_argument('--recompile', help='recompile all agents.', action='store_true', default=False)
        parser.add_argument('-m', metavar='<memlimit>', help='set memory limit [MB] (default 50 MB).', default=50,
                            type=int)

        self.argument_values = vars(parser.parse_args())


class KernelPrepareConfiguration:
    __metaclass__ = Singleton
    global default_section, default_config

    __config_section = default_section
    __config_default = default_config

    def __init__(self, initial=True):
        if initial:
            self.argument_values = None
            self.config_values = None
            self.__load_arguments()
            self.__load_config()
            self.load_old_state = False

    def __load_config(self):
        self.config_values = ConfigReader(os.path.dirname(sys.argv[0]) + "/kafl.ini", self.__config_section,
                                          self.__config_default).get_values()

    def __load_arguments(self):
        # modes = ["m32", "m64"]
        # modes_help= 'm32\tpack and compile as an i386   executable.\n'\
        #            'm64\tpack and compile as an x86-64 executable.\n'

        parser = ArgsParser(formatter_class=argparse.RawTextHelpFormatter)

        parser.add_argument('agent_file', metavar='<Agent Executable>', action=FullPath, type=parse_is_file,
                            help='path to the agent executable file.')
        parser.add_argument('kmods', metavar='<Kernel Moduls>', action=MapFullPaths, type=parse_is_file, nargs="+",
                            help='path to the main kernel module file and all dependencies.')
        parser.add_argument('output_dir', metavar='<Output Directory>', action=FullPath, type=parse_is_dir,
                            help='path to the output directory.')
        parser.add_argument('--recompile', help='recompile all agents.', action='store_true', default=False)

        self.argument_values = vars(parser.parse_args())


class InfoConfiguration:
    __metaclass__ = Singleton
    global default_section, default_config

    __config_section = default_section
    __config_default = default_config

    def __init__(self, initial=True):
        if initial:
            self.argument_values = None
            self.config_values = None
            self.__load_arguments()
            self.__load_config()
            self.load_old_state = False

    def __load_config(self):
        self.config_values = ConfigReader(os.path.dirname(sys.argv[0]) + "/kafl.ini", self.__config_section,
                                          self.__config_default).get_values()

    def __load_arguments(self):

        parser = ArgsParser(formatter_class=argparse.RawTextHelpFormatter)
        subparsers = parser.add_subparsers()

        parser_vm = subparsers.add_parser('VM', help="Full Virtual Machine Mode (RAM File / Overlay Files)",
                                          formatter_class=argparse.RawTextHelpFormatter)
        parser_vm.add_argument('ram_file', metavar='<RAM File>', action=FullPath, type=parse_is_file,
                               help='Path to the RAM file.')
        parser_vm.add_argument('overlay_dir', metavar='<Overlay Directory>', action=FullPath, type=parse_is_dir,
                               help='Path to the overlay directory.')
        parser.add_argument('-S', required=False, metavar='Snapshot', help='specifiy snapshot title (default: kafl).',
                            default="kafl", type=str)

        parser_kernel = subparsers.add_parser('Kernel', help="Lightweight Linux Mode (Kernel Image / initramfs)",
                                              formatter_class=argparse.RawTextHelpFormatter)
        parser_kernel.add_argument('kernel', metavar='<Kernel Image>', action=FullPath, type=parse_is_file,
                                   help='Path to the Kernel image.')
        parser_kernel.add_argument('initramfs', metavar='<Initramfs File>', action=FullPath, type=parse_is_file,
                                   help='Path to the initramfs file.')

        for sparser in [parser_vm, parser_kernel]:
            sparser.add_argument('executable', metavar='<Info Executable>', action=FullPath, type=parse_is_file,
                                 help='path to the info executable (kernel address dumper).')
            sparser.add_argument('mem', metavar='<RAM Size>', help='size of virtual RAM (default: 300).', default=300,
                                 type=int)
            sparser.add_argument('-v', required=False, help='enable verbose mode (./debug.log).', action='store_true',
                                 default=False)
            sparser.add_argument('-macOS', required=False, help='enable macOS Support (requires Apple OSK)',
                                 action='store_true', default=False)

        self.argument_values = vars(parser.parse_args())


class DebugConfiguration:
    __metaclass__ = Singleton
    global default_section, default_config

    __config_section = default_section
    __config_default = default_config

    def __init__(self, initial=True):
        if initial:
            self.argument_values = None
            self.config_values = None
            self.__load_arguments()
            self.__load_config()
            self.load_old_state = False

    def __load_config(self):
        self.config_values = ConfigReader(os.path.dirname(sys.argv[0]) + "/kafl.ini", self.__config_section,
                                          self.__config_default).get_values()

    def __load_arguments(self):

        debug_modes = ["benchmark", "trace", "trace-qemu", "noise", "noise-multiple", "printk", "redqueen",
                       "redqueen-qemu", "cov", "verify"]

        debug_modes_help = '<benchmark>\t\tperform performance benchmark\n' \
                           '<trace>\t\t\tperform trace run\n' \
                           '<trace-qemu>\t\tperform trace run and print QEMU stdout\n' \
                           '<noise>\t\t\tperform run and messure nondeterminism\n' \
                           '<noise-multiple>\t\t\tperform multiple runs and messure nondeterminism\n' \
                           '<printk>\t\t\tredirect printk calls to kAFL\n' \
                           '<redqueen>\t\trun redqueen debugger\n' \
                           '<redqueen-qemu>\trun redqueen debugger and print QEMU stdout\n' \
                           '<cov>\tget coverage infomation for IDA Pro\n' \
                           '<verify>\t\trun verifcation steps\n'

        parser = ArgsParser(formatter_class=argparse.RawTextHelpFormatter)
        subparsers = parser.add_subparsers()

        parser_vm = subparsers.add_parser('VM', help="Full Virtual Machine Mode (RAM File / Overlay Files)",
                                          formatter_class=argparse.RawTextHelpFormatter)
        parser_vm.add_argument('ram_file', metavar='<RAM File>', action=FullPath, type=parse_is_file,
                               help='Path to the RAM file.')
        parser_vm.add_argument('overlay_dir', metavar='<Overlay Directory>', action=FullPath, type=parse_is_dir,
                               help='Path to the overlay directory.')
        parser.add_argument('-S', required=False, metavar='Snapshot', help='specifiy snapshot title (default: kafl).',
                            default="kafl", type=str)

        parser_kernel = subparsers.add_parser('Kernel', help="Lightweight Linux Mode (Kernel Image / initramfs)",
                                              formatter_class=argparse.RawTextHelpFormatter)
        parser_kernel.add_argument('kernel', metavar='<Kernel Image>', action=FullPath, type=parse_is_file,
                                   help='Path to the Kernel image.')
        parser_kernel.add_argument('initramfs', metavar='<Initramfs File>', action=FullPath, type=parse_is_file,
                                   help='Path to the initramfs file.')

        for sparser in [parser_vm, parser_kernel]:
            sparser.add_argument('executable', metavar='<Agent>', action=FullPath, type=parse_is_file,
                                 help='path to the agent executable.')
            sparser.add_argument('mem', metavar='<RAM Size>', help='size of virtual RAM (default: 300).', default=300,
                                 type=int)

            sparser.add_argument('-I', required=False, metavar='<Dict-File>', help='import dictionary to fuzz.',
                                 default=None, type=parse_is_file)

            sparser.add_argument('work_dir', metavar='<Working Directory>', action=FullPath, type=create_dir,
                                 help='Path to the working directory.')

            sparser.add_argument('-v', required=False, help='enable verbose mode (./debug.log).', action='store_true',
                                 default=False)
            sparser.add_argument('-macOS', required=False, help='enable macOS Support (requires Apple OSK)',
                                 action='store_true', default=False)

            sparser.add_argument('-binary', required=False,
                                 help='path to original binary (for debug information / line coverage)',
                                 action=FullPath, default=None)

            sparser.add_argument('payload', metavar='<Payload Data>', action=MapFullPaths, type=parse_is_file,
                                 nargs="+", help='path to the payload file.')

            sparser.add_argument('debug_mode', metavar='<Debug Mode>', choices=debug_modes, help=debug_modes_help)

            sparser.add_argument('-R', required=False, help='disable fast reload mode', action='store_false',
                                 default=True)

            sparser.add_argument('-ip0', required=False, metavar='<IP-Filter 0>', type=parse_range_ip_filter,
                                 help='instruction pointer filter range 0')
            sparser.add_argument('-ip1', required=False, metavar='<IP-Filter 1>', type=parse_range_ip_filter,
                                 help='instruction pointer filter range 1 (not supported in this version)')
            sparser.add_argument('-ip2', required=False, metavar='<IP-Filter 2>', type=parse_range_ip_filter,
                                 help='instruction pointer filter range 2 (not supported in this version)')
            sparser.add_argument('-ip3', required=False, metavar='<IP-Filter 3>', type=parse_range_ip_filter,
                                 help='instruction pointer filter range 3 (not supported in this version)')

            sparser.add_argument('-i', metavar='<Iterations>', help='debug iterations (default: 5)', default=5,
                                 type=int)
            sparser.add_argument('-V', required=False,
                                 help='lazy vAPIC resets in VM reload mode (results in performance boost, but may increase non determinism)',
                                 action='store_true', default=False)

        self.argument_values = vars(parser.parse_args())


class FuzzerConfiguration:
    __metaclass__ = Singleton
    global default_section, default_config

    __config_section = default_section
    __config_default = default_config

    def __init__(self, emulated_arguments=None, skip_args=False):
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
        f = open(os.path.dirname(sys.argv[0]) + "/kafl.ini", "w")
        config = ConfigParser.ConfigParser()
        config.add_section(self.__config_section)
        for k, v in self.__config_default.items():
            if v is None or (type(v) is str and v == ""):
                config.set(self.__config_section, k, "\"\"")
            else:
                config.set(self.__config_section, k, v)
        config.write(f)
        f.close()

    def __load_config(self):
        self.config_values = ConfigReader(os.path.dirname(sys.argv[0]) + "/kafl.ini", self.__config_section,
                                          self.__config_default).get_values()

    def __load_arguments(self):

        eval_modes = ["1", "2", "3", "4", "5"]
        eval_modes_help = '1\tDefault\n' \
                          '2\tDefault (ignore bit-counts)\n' \
                          '3\t`return (-node.level, perf, node.fav_bits, 1/node.performance)`\n' \
                          '4\tDefault + Havoc on demand.\n' \
                          '5\tDefault + Havoc on demand (ignore bit-counts).\n'

        parser = ArgsParser(formatter_class=argparse.RawTextHelpFormatter)
        subparsers = parser.add_subparsers()

        parser_vm = subparsers.add_parser('VM', help="Full Virtual Machine Mode (RAM File / Overlay Files)",
                                          formatter_class=argparse.RawTextHelpFormatter)
        parser_vm.add_argument('ram_file', metavar='<RAM File>', action=FullPath, type=parse_is_file,
                               help='Path to the RAM file.')
        parser_vm.add_argument('overlay_dir', metavar='<Overlay Directory>', action=FullPath, type=parse_is_dir,
                               help='Path to the overlay directory.')
        parser.add_argument('-S', required=False, metavar='Snapshot', help='specifiy snapshot title (default: kafl).',
                            default="kafl", type=str)

        parser_kernel = subparsers.add_parser('Kernel', help="Lightweight Linux Mode (Kernel Image / initramfs)",
                                              formatter_class=argparse.RawTextHelpFormatter)
        parser_kernel.add_argument('kernel', metavar='<Kernel Image>', action=FullPath, type=parse_is_file,
                                   help='Path to the Kernel image.')
        parser_kernel.add_argument('initramfs', metavar='<Initramfs File>', action=FullPath, type=parse_is_file,
                                   help='Path to the initramfs file.')

        for sparser in [parser_vm, parser_kernel]:
            sparser.add_argument('executable', metavar='<Fuzzer Executable>', action=FullPath, type=parse_is_file,
                                 help='Path to the fuzzer executable.')
            sparser.add_argument('mem', metavar='<RAM Size>', help='Size of virtual RAM (default: 300).', default=300,
                                 type=int)
            sparser.add_argument('seed_dir', metavar='<Seed Directory>', action=FullPath, type=parse_is_dir,
                                 help='Path to the seed directory.')
            sparser.add_argument('work_dir', metavar='<Working Directory>', action=FullPath, type=create_dir,
                                 help='Path to the working directory.')

            sparser.add_argument('-ip0', required=True, metavar='<IP-Filter 0>', type=parse_range_ip_filter,
                                 help='instruction pointer filter range 0')
            sparser.add_argument('-ip1', required=False, metavar='<IP-Filter 1>', type=parse_range_ip_filter,
                                 help='instruction pointer filter range 1 (not supported in this version)')
            sparser.add_argument('-ip2', required=False, metavar='<IP-Filter 2>', type=parse_range_ip_filter,
                                 help='instruction pointer filter range 2 (not supported in this version)')
            sparser.add_argument('-ip3', required=False, metavar='<IP-Filter 3>', type=parse_range_ip_filter,
                                 help='instruction pointer filter range 3 (not supported in this version)')

            sparser.add_argument('-p', required=False, metavar='<Process Number>',
                                 help='number of worker processes to start.', default=1, type=int)
            sparser.add_argument('-t', required=False, metavar='<Task Number>',
                                 help='tasks per worker request to provide.', default=1, type=int)
            sparser.add_argument('-v', required=False, help='enable verbose mode (./debug.log).', action='store_true',
                                 default=False)
            sparser.add_argument('-g', required=False, help='disable GraphViz drawing.', action='store_false',
                                 default=True)
            sparser.add_argument('-s', required=False, help='skip zero bytes during deterministic fuzzing stages.',
                                 action='store_true', default=False)
            sparser.add_argument('-b', required=False, help='enable usage of ringbuffer for findings.',
                                 action='store_true', default=False)
            sparser.add_argument('-d', required=False, help='disable usage of AFL-like effector maps.',
                                 action='store_false', default=True)
            sparser.add_argument('--Purge', required=False, help='purge the working directory.', action='store_true',
                                 default=False)
            sparser.add_argument('-i', required=False, type=parse_ignore_range, metavar="[0-131072]",
                                 help='range of bytes to skip during deterministic fuzzing stages (0-128KB).',
                                 action='append')
            sparser.add_argument('-e', required=False, help='disable evaluation mode.', action='store_false',
                                 default=True)
            sparser.add_argument('-D', required=False, help='skip deterministic stages (dumb mode).',
                                 action='store_false', default=True)
            sparser.add_argument('-I', required=False, metavar='<Dict-File>', help='import dictionary to fuzz.',
                                 default=None, type=parse_is_file)
            sparser.add_argument('-macOS', required=False, help='enable macOS Support (requires Apple OSK)',
                                 action='store_true', default=False)
            sparser.add_argument('-f', required=False, help='disable fancy UI', action='store_false', default=True)
            sparser.add_argument('-r', required=False, help='enable fast redqueen insertion algorithm',
                                 action='store_true', default=False)
            sparser.add_argument('-n', required=False, help='disable filter sampling', action='store_false',
                                 default=True)
            sparser.add_argument('-l', required=False, help='enable UI log output', action='store_true', default=False)
            sparser.add_argument('-R', required=False, help='disable fast reload mode', action='store_false',
                                 default=True)
            sparser.add_argument('-V', required=False,
                                 help='lazy vAPIC resets in VM reload mode (results in performance boost, but may increase non determinism)',
                                 action='store_true', default=False)

            sparser.add_argument('-enable_se', required=False, help='enable SE mode', action='store_true',
                                 default=False)
            sparser.add_argument('-only_se', required=False,
                                 help='enable SE mode and disable other redqueen techniques.', action='store_true',
                                 default=False)
            sparser.add_argument('-fix_hashes', required=False, help='enable checksum fix module', action='store_true',
                                 default=False)
            sparser.add_argument('-hammer_jmp_tables', required=False, help='enable jump table hammering',
                                 action='store_true', default=False)

            sparser.add_argument('-eval_mode', metavar='<Mode>', choices=eval_modes, help=eval_modes_help, default="1",
                                 required=False)
            sparser.add_argument('-cpu_affinity', help="set affinity to core x", type=int, required=False)

        self.argument_values = vars(parser.parse_args())
        print(self.argument_values)

    def save_data(self):
        """
        Method to store an entire config state to JSON file...
        """
        with open(self.argument_values['work_dir'] + "/config.json", 'w') as outfile:
            json.dump(self.__dict__, outfile, default=json_dumper)

    def load_data(self):
        """
        Method to load an entire config state from JSON file...
        """
        with open(self.argument_values['work_dir'] + "/config.json", 'r') as infile:
            dump = json.load(infile)
            for key, value in dump.iteritems():
                setattr(self, key, value)
        self.load_old_state = True
