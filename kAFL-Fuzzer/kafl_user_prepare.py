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
import tarfile
import uuid

import common.color
from common.color import WARNING_PREFIX, ERROR_PREFIX, FAIL, WARNING, ENDC, OKGREEN, BOLD, OKBLUE, INFO_PREFIX, OKGREEN
from common.self_check import self_check
from common.util import ask_for_permission

__author__ = 'sergej'


def create_dependencies(target_binary_path, tmp_folder, objcopy_type, ld_type):
    result_string = ""
    print("\n" + OKGREEN + INFO_PREFIX + "Gathering dependencies of " + target_binary_path + ENDC)
    cmd = "lddtree -l " + target_binary_path
    try:
        proc = subprocess.Popen(cmd.split(" "), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if proc.wait() is not 0:
            raise Exception(proc.stderr.read())

        dependencies = proc.stdout.read().rstrip().split("\n")

        library_name = []

        libasan_name = ""

        # First line contains only the filename
        i = 1
        for d in dependencies[1:]:
            print(OKGREEN + INFO_PREFIX + "  => " + d + ENDC)
            shutil.copy2(d, tmp_folder + str(i))
            execute(("objcopy -I binary -O " + objcopy_type + " -B i386 " + str(i) + " " + str(i) + ".o").split(" "),
                    tmp_folder, print_cmd=True)
            library_name.append(os.path.basename(d))
            i += 1

            if "libasan" in d:
                libasan_name = os.path.basename(d)

        if len(library_name) != 0:
            execute(("ld -r -m " + ld_type + " " + " ".join("%d.o" % i for i in range(1, i)) + " -o libraries.o").split(
                " "), tmp_folder, print_cmd=True)
        # else:
        #	execute(("ld -r -m " + ld_type + " " + " -o libraries.o").split(" "), tmp_folder, print_cmd=True)
        if (i >= 1):
            for e in range(1, i):
                result_string += "extern uint8_t _binary_" + str(e) + "_start;\n"
                result_string += "extern uint8_t _binary_" + str(e) + "_end;\n"
                result_string += "extern uint8_t _binary_" + str(e) + "_size;\n"

            result_string += "uint8_t* library_address_start[] = {" + ", ".join(
                "&_binary_%d_start" % i for i in range(1, i)) + "};\n"
            result_string += "uint8_t* library_address_end[] = {" + ", ".join(
                "&_binary_%d_end" % i for i in range(1, i)) + "};\n"
            result_string += "uint8_t* library_size[] = {" + ", ".join(
                "&_binary_%d_size" % i for i in range(1, i)) + "};\n"
            result_string += "char* library_name[] = {" + ", ".join("\"%s\"" % e for e in library_name) + "};\n"
            result_string += "uint32_t libraries = " + str(i - 1) + ";\n"
            result_string += "char* libasan_name = \"" + libasan_name + "\";\n"
        else:
            esult_string += "uint8_t* library_address_start[] = {" "};\n"
            result_string += "uint8_t* library_address_end[] = {" "};\n"
            result_string += "uint8_t* library_size[] = {" "};\n"
            result_string += "char* library_name[] = {};\n"
            result_string += "uint32_t libraries = 0;\n"
            result_string += "char* libasan_name = \"\";\n"

    # print(result_string)

    except Exception as e:
        print(FAIL + "Error while running lddtree: " + str(e) + ENDC)

    return result_string


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
        print(FAIL + "Error while executing " + " ".join(cmd) + ENDC)


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


def check_memlimit(memlimit, mode32):
    if memlimit < 5:
        print(FAIL + ERROR_PREFIX + "Memlimit to low..." + ENDC)
        return False
    if memlimit >= 2048 and mode32:
        print(FAIL + ERROR_PREFIX + "Memlimit to high (x86 mode)..." + ENDC)
        return False
    return True


def checks(config):
    if not os.path.isdir(config.config_values["AGENTS-FOLDER"] + "/linux_x86_64-userspace/"):
        print(FAIL + ERROR_PREFIX + "Wrong path to \"AGENTS-FOLDER\" configured..." + ENDC)
        return False

    if (config.argument_values["recompile"]):
        print(OKGREEN + INFO_PREFIX + "Recompiling..." + ENDC)
        execute(["bash", "compile.sh"], config.config_values["AGENTS-FOLDER"] + "/linux_x86_64-userspace/",
                print_output=True)

    if not os.path.isdir(config.config_values["AGENTS-FOLDER"] + "/linux_x86_64-userspace/bin/"):
        print(FAIL + ERROR_PREFIX + "Userspace agents are not precompiled..." + ENDC)

        print(WARNING + WARNING_PREFIX + "Would you like to compile all agents now?" + ENDC)
        if not ask_for_permission("COMPILE", " to compile agents:", color=WARNING):
            return False
        else:
            execute(["sh", "compile.sh"], config.config_values["AGENTS-FOLDER"])

    files = ["userspace_loader_32.o", "ld_preload_info_32.o", "ld_preload_fuzz_32.o", "userspace_loader_64.o",
             "ld_preload_info_64.o", "ld_preload_fuzz_64.o"]

    for file in files:
        if not os.path.isfile(config.config_values["AGENTS-FOLDER"] + "/linux_x86_64-userspace/bin/" + file):
            print(FAIL + ERROR_PREFIX + "File \"" + file + "\" is missing (try to recompile agents?)..." + ENDC)
            return False

    return True


def compile(config):
    if not check_memlimit(config.argument_values["m"], config.argument_values["mode"] == "m32"):
        return

    elf_mode = check_elf(config.argument_values["binary_file"])
    if not elf_mode:
        return

    print(OKGREEN + INFO_PREFIX + "Executable architecture is Intel " + elf_mode + "-bit ..." + ENDC)
    if (elf_mode == "32" and config.argument_values["mode"] == "m64") or (
            elf_mode == "64" and config.argument_values["mode"] == "m32"):
        print(WARNING + WARNING_PREFIX + "Executable architecture mismatch!" + ENDC)
        if not ask_for_permission("IGNORE", " to continue:", color=WARNING):
            return

    if config.argument_values["mode"] == "m64":
        objcopy_type = "elf64-x86-64"
        mode = "64"
        ld_type = "elf_x86_64"
    else:
        objcopy_type = "elf32-i386"
        mode = "32"
        ld_type = "elf_i386"

    tmp_folder = "/tmp/" + str(uuid.uuid4()) + "/"
    os.makedirs(tmp_folder)
    print(OKGREEN + INFO_PREFIX + "Temp folder is \"" + tmp_folder + "\" ..." + ENDC)

    try:
        print(OKGREEN + INFO_PREFIX + "Creating target.o file ..." + ENDC)
        shutil.copy2(config.argument_values["binary_file"], tmp_folder + "target")
        execute(("objcopy -I binary -O " + objcopy_type + " -B i386 target target.o").split(" "), tmp_folder,
                print_cmd=True)

        print(OKGREEN + INFO_PREFIX + "Creating ld_preload_target_info.o file ..." + ENDC)
        shutil.copy2(
            config.config_values["AGENTS-FOLDER"] + "/linux_x86_64-userspace/bin/" + "ld_preload_info_" + mode + ".o",
            tmp_folder + "ld_preload_info.o")
        execute(("gcc -m" + mode + " -shared -fPIC ld_preload_info.o -o ld_preload_target -ldl").split(" "), tmp_folder,
                print_cmd=True)
        execute(
            ("objcopy -I binary -O " + objcopy_type + " -B i386 ld_preload_target ld_preload_target_info.o").split(" "),
            tmp_folder, print_cmd=True)

        # Create library archive
        # creade_dependencies_archive(config.argument_values["binary_file"], tmp_folder + "libarchive")
        # execute(("objcopy -I binary -O " + objcopy_type + " -B i386 libarchive libarchive.o").split(" "), tmp_folder, print_cmd=True)

        print(OKGREEN + INFO_PREFIX + "Creating argv.o file ..." + ENDC)
        argv_template = "#include <stdint.h>\n#include <stddef.h>\n"
        if len(config.argument_values["args"]) != 0:
            value = str(1)
            argv_template += "char* args[] = {\"/tmp/target_executable\", "
            for e in config.argument_values["args"].split(" "):
                argv_template += "\"" + e + "\", "
            argv_template += "(char*)0};\n"
        else:
            value = str(0)
            argv_template += "char* args[] = {\"/tmp/target_executable\", (char*)0};\n"

        argv_template += "uint8_t extra_args = " + str(value) + ";\n"

        if len(config.argument_values["file"]) != 0:
            argv_template += "uint8_t stdin_mode = 0;\n"
            argv_template += "char* output_filename = \"" + config.argument_values["file"] + "\";\n"
        else:
            argv_template += "char* output_filename = \"\";\n"
            argv_template += "uint8_t stdin_mode = 1;\n"

        # Check whether the target must be linked against libasan
        try:
            if "libasan" in subprocess.check_output(["ldd", config.argument_values["binary_file"]]).decode('UTF-8'):
                argv_template += "uint8_t asan_enabled = 1;\n"
            else:
                argv_template += "uint8_t asan_enabled = 0;\n"
        except:
            argv_template += "uint8_t asan_enabled = 0;\n"

        argv_template += "uint32_t memlimit = " + str(config.argument_values["m"]) + ";\n"

        f = open(tmp_folder + "argv.c", "w")
        f.write(argv_template)
        f.close()

        argv_template += create_dependencies(config.argument_values["binary_file"], tmp_folder, objcopy_type, ld_type)

        print("------------------------")
        print(argv_template)
        print("------------------------")

        f = open(tmp_folder + "argv_libraries.c", "w")
        f.write(argv_template)
        f.close()

        execute(("gcc -m" + mode + " -c argv.c -o argv.o").split(" "), cwd=tmp_folder, print_cmd=True)
        execute(("gcc -m" + mode + " -c argv_libraries.c -o argv_libraries.o").split(" "), cwd=tmp_folder,
                print_cmd=True)

        print(OKGREEN + INFO_PREFIX + "Creating ld_preload_target_fuzz.o file ..." + ENDC)
        shutil.copy2(
            config.config_values["AGENTS-FOLDER"] + "/linux_x86_64-userspace/bin/" + "ld_preload_fuzz_" + mode + ".o",
            tmp_folder + "ld_preload_fuzz.o")
        execute(("gcc -m" + mode + " -shared -fPIC argv.o ld_preload_fuzz.o -o ld_preload_target -ldl").split(" "),
                tmp_folder, print_cmd=True)
        execute(
            ("objcopy -I binary -O " + objcopy_type + " -B i386 ld_preload_target ld_preload_target_fuzz.o").split(" "),
            tmp_folder, print_cmd=True)

        if os.path.isfile(tmp_folder + "/libraries.o"):
            # Create the final executables
            print(OKGREEN + INFO_PREFIX + "Creating info_binary file ..." + ENDC)
            shutil.copy2(config.config_values[
                             "AGENTS-FOLDER"] + "/linux_x86_64-userspace/bin/" + "userspace_loader_" + mode + ".o",
                         tmp_folder + "userspace_loader.o")
            execute((
                    "gcc -m" + mode + " argv_libraries.o userspace_loader.o target.o ld_preload_target_info.o libraries.o -o info_binary").split(
                " "), tmp_folder, print_cmd=True)

            print(OKGREEN + INFO_PREFIX + "Creating fuzz_binary file ..." + ENDC)
            shutil.copy2(config.config_values[
                             "AGENTS-FOLDER"] + "/linux_x86_64-userspace/bin/" + "userspace_loader_" + mode + ".o",
                         tmp_folder + "userspace_loader.o")
            execute((
                    "gcc -m" + mode + " argv_libraries.o userspace_loader.o target.o ld_preload_target_fuzz.o libraries.o -o fuzz_binary").split(
                " "), tmp_folder, print_cmd=True)
        else:
            # Create the final executables
            print(OKGREEN + INFO_PREFIX + "Creating info_binary file ..." + ENDC)
            shutil.copy2(config.config_values[
                             "AGENTS-FOLDER"] + "/linux_x86_64-userspace/bin/" + "userspace_loader_" + mode + ".o",
                         tmp_folder + "userspace_loader.o")
            execute((
                    "gcc -m" + mode + " argv_libraries.o userspace_loader.o target.o ld_preload_target_info.o -o info_binary").split(
                " "), tmp_folder, print_cmd=True)

            print(OKGREEN + INFO_PREFIX + "Creating fuzz_binary file ..." + ENDC)
            shutil.copy2(config.config_values[
                             "AGENTS-FOLDER"] + "/linux_x86_64-userspace/bin/" + "userspace_loader_" + mode + ".o",
                         tmp_folder + "userspace_loader.o")
            execute((
                    "gcc -m" + mode + " argv_libraries.o userspace_loader.o target.o ld_preload_target_fuzz.o -o fuzz_binary").split(
                " "), tmp_folder, print_cmd=True)

        shutil.copy2(tmp_folder + "info_binary", config.argument_values["output_dir"] + "/" + os.path.basename(
            config.argument_values["binary_file"]) + "_info")
        shutil.copy2(tmp_folder + "fuzz_binary", config.argument_values["output_dir"] + "/" + os.path.basename(
            config.argument_values["binary_file"]) + "_fuzz")
    finally:
        print(OKGREEN + INFO_PREFIX + "Deleting temp folder ..." + ENDC)
        shutil.rmtree(tmp_folder)

    print(OKGREEN + INFO_PREFIX + "Done !\n" + ENDC)
    print(OKGREEN + "Generated files:" + ENDC)
    print(OKBLUE + BOLD + " ==>  " + config.argument_values["output_dir"] + "/" + os.path.basename(
        config.argument_values["binary_file"]) + "_info" + ENDC)
    print(OKBLUE + BOLD + " ==>  " + config.argument_values["output_dir"] + "/" + os.path.basename(
        config.argument_values["binary_file"]) + "_fuzz" + ENDC)


def main():
    f = open("help.txt")
    for line in f:
        print(line.replace("\n", ""))
    f.close()

    print("<< " + BOLD + OKGREEN + sys.argv[0] + ": kAFL Binary Packer for Userspace Fuzzing " + ENDC + ">>\n")

    if not self_check():
        return 1

    from common.config import UserPrepareConfiguration
    config = UserPrepareConfiguration()

    if not checks(config):
        return False

    compile(config)


if __name__ == "__main__":
    main()
