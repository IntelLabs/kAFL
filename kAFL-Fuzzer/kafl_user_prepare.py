#!/usr/bin/env python3
#
# Copyright (C) 2017-2019 Sergej Schumilo, Cornelius Aschermann
# Copyright (C) 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Helper script to harness simple Linux userspace binaries for use within a kAFL guest VM.
"""

import argparse
import os
import shutil
import subprocess
import sys
import tarfile
import uuid

from common.color import WARNING_PREFIX, ERROR_PREFIX, FAIL, WARNING, ENDC, OKGREEN, BOLD, OKBLUE, INFO_PREFIX, OKGREEN
from common.self_check import self_check


KAFL_ROOT = os.path.dirname(os.path.realpath(__file__)) + "/"
KAFL_BANNER = KAFL_ROOT + "banner.txt"
KAFL_CONFIG = KAFL_ROOT + "kafl.ini"

def create_dependencies(target_binary_path, tmp_folder, objcopy_type, ld_type):
    result_string = ""
    is_asan_build = False
    print("\n" + OKGREEN + INFO_PREFIX + "Gathering dependencies of " + target_binary_path + ENDC)
    cmd = "lddtree -l " + target_binary_path
    try:
        proc = subprocess.Popen(cmd.split(" "), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if proc.wait() != 0:
            raise Exception(proc.stderr.read())

        dependencies = proc.stdout.read().decode().rstrip().split("\n")

        library_name = []

        libasan_name = ""

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
                is_asan_build = True

        if len(library_name) != 0:
            execute(("ld -r -m " + ld_type + " " + " ".join("%d.o" % i for i in range(1, i)) + " -o libraries.o").split(
                " "), tmp_folder, print_cmd=True)
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
            result_string += "uint8_t* library_address_start[] = {" "};\n"
            result_string += "uint8_t* library_address_end[] = {" "};\n"
            result_string += "uint8_t* library_size[] = {" "};\n"
            result_string += "char* library_name[] = {};\n"
            result_string += "uint32_t libraries = 0;\n"
            result_string += "char* libasan_name = \"\";\n"

    except Exception as e:
        print(FAIL + "Error while running lddtree: " + str(e) + ENDC)

    return result_string, is_asan_build


def execute(cmd, cwd, print_output=True, print_cmd=False):
    if print_cmd:
        print(OKBLUE + "\t  " + "Executing: " + " ".join(cmd) + ENDC)

    proc = subprocess.Popen(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if print_output:
        while True:
            output = proc.stdout.readline()
            if output:
                print(output.decode()),
            else:
                break
        while True:
            output = proc.stderr.readline()
            if output:
                print(FAIL + output.decode() + ENDC),
            else:
                break
    if proc.wait() != 0:
        print(FAIL + "Error while executing " + " ".join(cmd) + ENDC)


def check_elf(file):
    proc = subprocess.Popen(("file " + file).split(" "), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output = proc.stdout.readline().decode()
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
        return False

    files = ["userspace_loader_32.o", "ld_preload_info_32.o", "ld_preload_fuzz_32.o", "userspace_loader_64.o",
             "ld_preload_info_64.o", "ld_preload_fuzz_64.o"]

    for file in files:
        if not os.path.isfile(config.config_values["AGENTS-FOLDER"] + "/linux_x86_64-userspace/bin/" + file):
            print(FAIL + ERROR_PREFIX + "File \"" + file + "\" is missing (try to recompile agents?)..." + ENDC)
            return False

    return True


def compile(config):
    if not check_memlimit(config.argument_values["m"], config.argument_values["mode"] == "m32"):
        return False

    elf_mode = check_elf(config.argument_values["binary_file"])
    if not elf_mode:
        return False

    print(OKGREEN + INFO_PREFIX + "Executable architecture is Intel " + elf_mode + "-bit ..." + ENDC)
    if (elf_mode == "32" and config.argument_values["mode"] == "m64") or (
            elf_mode == "64" and config.argument_values["mode"] == "m32"):
        print(WARNING + WARNING_PREFIX + "Executable architecture mismatch!" + ENDC)
        return False

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

        argv_res, is_asan_build = create_dependencies(config.argument_values["binary_file"], tmp_folder, objcopy_type, ld_type)
        argv_template += argv_res
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

        if is_asan_build or (config.argument_values["asan"]):
            print(WARNING + INFO_PREFIX + FAIL + "ASAN BINARY DETECTED => Disabling memlimits!" + ENDC)
            shutil.copy2(
                config.config_values["AGENTS-FOLDER"] + "/linux_x86_64-userspace/bin/" + "ld_preload_fuzz_" + mode + "_asan.o",
                tmp_folder + "ld_preload_fuzz.o")
        else:
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
            shutil.copy2(config.config_values["AGENTS-FOLDER"] + "/linux_x86_64-userspace/bin/" + "userspace_loader_" + mode + ".o",
                         tmp_folder + "userspace_loader.o")
            execute((
                                "gcc -static -m" + mode + " argv_libraries.o userspace_loader.o target.o ld_preload_target_info.o libraries.o -o info_binary").split(
                " "), tmp_folder, print_cmd=True)

            print(OKGREEN + INFO_PREFIX + "Creating fuzz_binary file ..." + ENDC)
            shutil.copy2(config.config_values["AGENTS-FOLDER"] + "/linux_x86_64-userspace/bin/" + "userspace_loader_" + mode + ".o",
                         tmp_folder + "userspace_loader.o")
            execute((
                                "gcc -static -m" + mode + " argv_libraries.o userspace_loader.o target.o ld_preload_target_fuzz.o libraries.o -o fuzz_binary").split(
                " "), tmp_folder, print_cmd=True)
        else:
            # Create the final executables
            print(OKGREEN + INFO_PREFIX + "Creating info_binary file ..." + ENDC)
            shutil.copy2(config.config_values["AGENTS-FOLDER"] + "/linux_x86_64-userspace/bin/" + "userspace_loader_" + mode + ".o",
                         tmp_folder + "userspace_loader.o")
            execute((
                                "gcc -static -m" + mode + " argv_libraries.o userspace_loader.o target.o ld_preload_target_info.o -o info_binary").split(
                " "), tmp_folder, print_cmd=True)

            print(OKGREEN + INFO_PREFIX + "Creating fuzz_binary file ..." + ENDC)
            shutil.copy2(config.config_values[
                             "AGENTS-FOLDER"] + "/linux_x86_64-userspace/bin/" + "userspace_loader_" + mode + ".o",
                         tmp_folder + "userspace_loader.o")
            execute((
                                "gcc -static -m" + mode + " argv_libraries.o userspace_loader.o target.o ld_preload_target_fuzz.o -o fuzz_binary").split(
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

    return True

def main():

    print(BOLD + OKGREEN + sys.argv[0] +
            ": kAFL Binary Packer for Userspace Fuzzing " + ENDC + "\n")

    if not self_check(KAFL_ROOT):
        sys.exit(os.EX_SOFTWARE)

    from common.config import UserPrepareConfiguration
    try:
        config = UserPrepareConfiguration(KAFL_CONFIG)
    except:
        sys.exit(os.EX_USAGE)

    if not checks(config):
        sys.exit(os.EX_USAGE)

    if not compile(config):
        sys.exit(os.EX_USAGE)


if __name__ == "__main__":
    try:
        main()
    except:
        sys.exit(os.EX_SOFTWARE)
