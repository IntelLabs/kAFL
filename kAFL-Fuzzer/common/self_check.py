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


import os
import subprocess
import sys
from fcntl import ioctl

import common.color
from common.color import WARNING_PREFIX, ERROR_PREFIX, FAIL, WARNING, ENDC


def check_if_nativ_lib_compiled():
    if not (os.path.exists(os.path.dirname(sys.argv[0]) + "/fuzzer/native/") and os.path.exists(
            os.path.dirname(sys.argv[0]) + "/fuzzer/native/bitmap.so")):
        print(WARNING + WARNING_PREFIX + "bitmap.so file does not exist. Compiling..." + ENDC)

        current_dir = os.getcwd()
        os.chdir(os.path.dirname(sys.argv[0]))
        p = subprocess.Popen(("gcc fuzzer/native/bitmap.c --shared -fPIC -O3 -o fuzzer/native/bitmap.so").split(" "),
                             stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
        if p.wait() != 0:
            print(FAIL + ERROR_PREFIX + "Compiling failed..." + ENDC)
        os.chdir(current_dir)
        return False
    return True


def check_if_installed(cmd):
    p = subprocess.Popen(("which " + cmd).split(" "), stdout=subprocess.PIPE, stdin=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    if p.wait() != 0:
        return False
    return True


def check_version():
    if sys.version_info < (2, 7, 0) or sys.version_info >= (3, 0, 0):
        print(FAIL + ERROR_PREFIX + "This script requires python 2.7 or higher (except for python 3.x)!" + ENDC)
        return False
    return True


def check_packages():
    try:
        import mmh3
    except ImportError:
        print(FAIL + ERROR_PREFIX + "Package 'mmh3' is missing!" + ENDC)
        return False

    try:
        import lz4
    except ImportError:
        print(FAIL + ERROR_PREFIX + "Package 'lz4' is missing!" + ENDC)
        return False

    try:
        import psutil
    except ImportError:
        print(FAIL + ERROR_PREFIX + "Package 'psutil' is missing!" + ENDC)
        return False

    try:
        import pygraphviz
    except ImportError:
        print(FAIL + ERROR_PREFIX + "Package 'pygraphviz' is missing!" + ENDC)
        return False

    if not check_if_installed("lddtree"):
        print(FAIL + ERROR_PREFIX + "Tool 'lddtree' is missing (Hint: run `sudo apt install pax-utils`)!" + ENDC)
        return False

    try:
        import ipdb
    except ImportError:
        print(FAIL + ERROR_PREFIX + "Package 'ipdb' is missing (Hint: run `sudo pip install ipdb`)!" + ENDC)
        return False

    try:
        import fastrand
    except ImportError:
        print(
            FAIL + ERROR_PREFIX + "Package 'fastrand' is missing (Hint: run `python setup.py install` in the fastrand folder)!" + ENDC)
        return False

    return True


def check_vmx_pt():
    from fcntl import ioctl

    KVMIO = 0xAE
    KVM_VMX_PT_SUPPORTED = KVMIO << (8) | 0xe4

    try:
        fd = open("/dev/kvm", "wb")
    except:
        print(FAIL + ERROR_PREFIX + "KVM is not loaded!" + ENDC)
        return False

    try:
        ret = ioctl(fd, KVM_VMX_PT_SUPPORTED, 0)
    except IOError:
        print(FAIL + ERROR_PREFIX + "VMX_PT is not loaded!" + ENDC)
        return False
    fd.close()

    if ret == 0:
        print(FAIL + ERROR_PREFIX + "Intel PT is not supported on this CPU!" + ENDC)
        return False

    return True


def check_apple_osk(config):
    if config.argument_values["macOS"]:
        if config.config_values["APPLE-SMC-OSK"] == "":
            print(FAIL + ERROR_PREFIX + "APPLE SMC OSK is missing in kafl.ini!" + ENDC)
            return False
    return True


def check_apple_ignore_msrs(config):
    if config.argument_values["macOS"]:
        try:
            f = open("/sys/module/kvm/parameters/ignore_msrs")
            if not 'Y' in f.read(1):
                print(
                    FAIL + ERROR_PREFIX + "KVM is not properly configured! Please execute the following command:" + ENDC + "\n\n\tsudo su\n\techo 1 > /sys/module/kvm/parameters/ignore_msrs\n")
                return False
            else:
                return True
        except:
            pass
        finally:
            f.close()
        print(FAIL + ERROR_PREFIX + "KVM is not ready?!" + ENDC)
        return False
    return True


def check_kafl_ini():
    if not os.path.exists(os.path.dirname(sys.argv[0]) + "/kafl.ini"):
        from common.config import FuzzerConfiguration
        FuzzerConfiguration(skip_args=True).create_initial_config()
        print(WARNING + WARNING_PREFIX + "kafl.ini file does not exist. Creating..." + ENDC)
        return False
    return True


def check_qemu_version(config):
    if not config.config_values["QEMU_KAFL_LOCATION"] or config.config_values["QEMU_KAFL_LOCATION"] == "":
        print(FAIL + ERROR_PREFIX + "QEMU_KAFL_LOCATION is not set in kafl.ini!" + ENDC)
        return False

    if not os.path.exists(config.config_values["QEMU_KAFL_LOCATION"]):
        print(FAIL + ERROR_PREFIX + "QEMU-PT executable does not exists..." + ENDC)
        return False

    output = ""
    try:
        proc = subprocess.Popen([config.config_values["QEMU_KAFL_LOCATION"], "-version"], stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        output = proc.stdout.readline()
        proc.wait()
    except:
        print(FAIL + ERROR_PREFIX + "Binary is not executable...?" + ENDC)
        return False
    if not ("QEMU-PT" in output and "(kAFL)" in output):
        print(FAIL + ERROR_PREFIX + "Wrong QEMU-PT executable..." + ENDC)
        return False
    return True


def self_check():
    if not check_kafl_ini():
        return False
    if not check_if_nativ_lib_compiled():
        return False
    if not check_version():
        return False
    if not check_packages():
        return False
    if not check_vmx_pt():
        return False
    return True


def post_self_check(config):
    if not check_apple_ignore_msrs(config):
        return False
    if not check_apple_osk(config):
        return False
    if not check_qemu_version(config):
        return False
    return True
