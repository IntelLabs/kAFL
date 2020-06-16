#!/usr/bin/env python
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
import os
import shutil
import subprocess
import sys
import toposort
import uuid

import common.color
from common.color import WARNING_PREFIX, ERROR_PREFIX, FAIL, WARNING, ENDC, OKGREEN, BOLD, OKBLUE, INFO_PREFIX, OKGREEN
from common.self_check import self_check
from common.util import ask_for_permission

__author__ = 'sergej'


def execute(cmd, cwd, print_output=True, print_cmd=False):
    if print_cmd:
        print(OKBLUE + "\t  " + "Executing: " + " ".join(cmd) + ENDC)

    proc = subprocess.Popen(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if print_output:
        while True:
            output = proc.stdout.readline()
            if output:
                print(output),
            else:
                break
        while True:
            output = proc.stderr.readline()
            if output:
                print(FAIL + output + ENDC),
            else:
                break
    if proc.wait() is not 0:
        print(FAIL + "Error while executing " + " ".join(cmd) + ENDC),


def get_kmod_dependencies(kmod):
    cmd = "modinfo " + kmod
    cmd = cmd.split(" ")
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    ouput = ""
    dep = ""
    name = ""
    while True:
        output = proc.stdout.readline()
        if output:
            if "depends:" in output:
                dep = output.replace(' ', '').replace('\n', '').split(":")[1]
                if len(dep) != 0:
                    dep = dep.split(",")
                else:
                    dep = []

            if "name:" in output:
                name = output.replace(' ', '').replace('\n', '').split(":")[1]
        else:
            break
    return dep, name


def check_elf(file):
    proc = subprocess.Popen(("file " + file).split(" "), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output = proc.stdout.readline()
    proc.wait()

    if not (not "ELF" in output and not "executable" in output and not "Intel" in output):
        if "32-bit" in output:
            return "32"
        elif "64-bit" in output:
            return "64"

    print(FAIL + ERROR_PREFIX + "File is not an Intel x86 / x86-64 executable..." + ENDC)
    return None


def checks(config):
    if not os.path.isdir(config.config_values["AGENTS-FOLDER"] + "/linux_x86_64/"):
        print(FAIL + ERROR_PREFIX + "Wrong path to \"AGENTS-FOLDER\" configured..." + ENDC)
        return False

    if (config.argument_values["recompile"]):
        print(OKGREEN + INFO_PREFIX + "Recompiling..." + ENDC)
        execute(["bash", "compile.sh"], config.config_values["AGENTS-FOLDER"] + "/linux_x86_64/", print_output=True)

    if not os.path.isdir(config.config_values["AGENTS-FOLDER"] + "/linux_x86_64/bin/"):
        print(FAIL + ERROR_PREFIX + "Kernel agents are not precompiled..." + ENDC)

        print(WARNING + WARNING_PREFIX + "Would you like to compile all agents now?" + ENDC)
        if not ask_for_permission("COMPILE", " to compile agents:", color=WARNING):
            return False
        else:
            execute(["sh", "compile.sh"], config.config_values["AGENTS-FOLDER"])

    files = ["info/info"]

    for file in files:
        if not os.path.isfile(config.config_values["AGENTS-FOLDER"] + "/linux_x86_64/bin/" + file):
            print(FAIL + ERROR_PREFIX + "File \"" + file + "\" is missing (try to recompile agents?)..." + ENDC)
            return False

    return True


def compile(config):
    files = {}
    dependencies = []
    file_map = {}

    for kmod in config.argument_values["kmods"]:
        deps, name = get_kmod_dependencies(kmod)

        file_map[name] = kmod

        files[name] = set(deps)
        for dep in deps:
            if dep not in dependencies:
                dependencies.append(dep)

    for file in files:
        if file in dependencies:
            dependencies.remove(file)

    if len(dependencies) != 0:

        print(FAIL + INFO_PREFIX + "Missing Kernel Module Dependencies: " + ENDC)
        for kmod in dependencies:
            print(FAIL + "\t    => " + kmod + ".ko" + ENDC)

        return

    results = (list(toposort.toposort(files)))

    print(OKGREEN + INFO_PREFIX + "Load order ..." + ENDC)

    files = []

    for result in results:
        for sub_result in result:
            print("\t    => " + str(os.path.basename(file_map[sub_result])))
            files.append(file_map[sub_result])

    tmp_folder = "/tmp/" + str(uuid.uuid4()) + "/"
    os.makedirs(tmp_folder)
    print(OKGREEN + INFO_PREFIX + "Temp folder is \"" + tmp_folder + "\" ..." + ENDC)

    objcopy_type = "elf64-x86-64"
    ld_type = "elf_x86_64"
    mode = "64"

    try:
        shutil.copy2(config.config_values["AGENTS-FOLDER"] + "/linux_x86_64/bin/loader/stage2_loader.o",
                     tmp_folder + "stage2_loader.o")

        print("\n" + OKGREEN + INFO_PREFIX + "Packing kernel modules ..." + ENDC)
        i = 0
        module_name = []
        for result in files:
            shutil.copy2(result, tmp_folder + str(i))
            execute(("objcopy -I binary -O " + objcopy_type + " -B i386 " + str(i) + " " + str(i) + ".o").split(" "),
                    tmp_folder, print_cmd=True)
            module_name.append(str(os.path.basename(result)))
            i += 1

        execute(("ld -r -m " + ld_type + " " + " ".join("%d.o" % i for i in range(i)) + " -o modules.o").split(" "),
                tmp_folder, print_cmd=True)

        argv_template = "#include <stdint.h>\n#include <stddef.h>\n"
        for e in range(i):
            argv_template += "extern uint8_t _binary_" + str(e) + "_start;\n"
            argv_template += "extern uint8_t _binary_" + str(e) + "_end;\n"
            argv_template += "extern uint8_t _binary_" + str(e) + "_size;\n"

        argv_template += "uint8_t* module_address_start[] = {" + ", ".join(
            "&_binary_%d_start" % i for i in range(i)) + "};\n"
        argv_template += "uint8_t* module_address_end[] = {" + ", ".join(
            "&_binary_%d_end" % i for i in range(i)) + "};\n"
        argv_template += "uint8_t* module_size[] = {" + ", ".join("&_binary_%d_size" % i for i in range(i)) + "};\n"
        argv_template += "char* module_name[] = {" + ", ".join("\"%s\"" % e for e in module_name) + "};\n"
        argv_template += "uint32_t modules = " + str(i) + ";\n"

        print("------------------------")
        print(argv_template)
        print("------------------------")

        f = open(tmp_folder + "argv.c", "w")
        f.write(argv_template)
        f.close()
        execute(("gcc -m" + mode + " -c argv.c -o argv.o").split(" "), cwd=tmp_folder, print_cmd=True)

        print(OKGREEN + INFO_PREFIX + "Creating target.o file ..." + ENDC)
        shutil.copy2(config.config_values["AGENTS-FOLDER"] + "/linux_x86_64/bin/info/info", tmp_folder + "target")
        execute(("objcopy -I binary -O " + objcopy_type + " -B i386 target target.o").split(" "), tmp_folder,
                print_cmd=True)

        # Create the final executables
        print(OKGREEN + INFO_PREFIX + "Creating info_binary file ..." + ENDC)
        execute(("gcc -m" + mode + " argv.o target.o modules.o stage2_loader.o -o info_binary").split(" "), tmp_folder,
                print_cmd=True)

        print(OKGREEN + INFO_PREFIX + "Creating target.o file ..." + ENDC)
        shutil.copy2(config.argument_values["agent_file"], tmp_folder + "target")
        execute(("objcopy -I binary -O " + objcopy_type + " -B i386 target target.o").split(" "), tmp_folder,
                print_cmd=True)

        print(OKGREEN + INFO_PREFIX + "Creating fuzz_binary file ..." + ENDC)
        execute(("gcc -m" + mode + " argv.o target.o modules.o stage2_loader.o -o fuzz_binary").split(" "), tmp_folder,
                print_cmd=True)

        shutil.copy2(tmp_folder + "info_binary", config.argument_values["output_dir"] + "/" + os.path.basename(
            config.argument_values["agent_file"]) + "_info")
        shutil.copy2(tmp_folder + "fuzz_binary", config.argument_values["output_dir"] + "/" + os.path.basename(
            config.argument_values["agent_file"]) + "_fuzz")

    finally:
        print(OKGREEN + INFO_PREFIX + "Deleting temp folder ..." + ENDC)
        shutil.rmtree(tmp_folder)

    print(OKGREEN + INFO_PREFIX + "Done !\n" + ENDC)
    print(OKGREEN + "Generated files:" + ENDC)
    print(OKBLUE + BOLD + " ==>  " + config.argument_values["output_dir"] + "/" + os.path.basename(
        config.argument_values["agent_file"]) + "_info" + ENDC)
    print(OKBLUE + BOLD + " ==>  " + config.argument_values["output_dir"] + "/" + os.path.basename(
        config.argument_values["agent_file"]) + "_fuzz" + ENDC)


def main():
    f = open("help.txt")
    for line in f:
        print(line.replace("\n", ""))
    f.close()

    print("<< " + BOLD + OKGREEN + sys.argv[
        0] + ": kAFL Agent / Module Packer for Linux Kernel Fuzzing " + ENDC + ">>\n")

    if not self_check():
        return 1

    from common.config import KernelPrepareConfiguration
    config = KernelPrepareConfiguration()

    if not checks(config):
        return False

    compile(config)


if __name__ == "__main__":
    main()
