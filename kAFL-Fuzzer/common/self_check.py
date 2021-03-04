# Copyright 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

import os
import subprocess
import sys
from fcntl import ioctl

from common.log import logger


def check_if_nativ_lib_compiled(kafl_root):
    if not (os.path.exists(kafl_root + "fuzzer/native/") and
            os.path.exists(kafl_root + "fuzzer/native/bitmap.so")):
        logger.warn("Attempting to build missing file fuzzer/native/bitmap.so ...")

        p = subprocess.Popen(("make -C " + kafl_root + "fuzzer/native/").split(" "),
                             stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE)

        if p.wait() != 0:
            logger.error("Build failed, please check..")
            return False
    return True


def check_if_installed(cmd):
    p = subprocess.Popen(("which " + cmd).split(" "), stdout=subprocess.PIPE, stdin=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    if p.wait() != 0:
        return False
    return True


def check_version():
    if sys.version_info < (3, 0, 0):
        logger.error("This script requires python 3!")
        return False
    return True


def check_packages():
    try:
        import msgpack
    except ImportError:
        logger.error("Package 'msgpack' is missing!")
        return False

    if msgpack.version < (0,6,0):
        logger.error("Package 'msgpack' is too old, try pip3 install -U msgpack!")
        return False

    try:
        import mmh3
    except ImportError:
        logger.error("Package 'mmh3' is missing!")
        return False

    try:
        import lz4
    except ImportError:
        logger.error("Package 'lz4' is missing!")
        return False

    try:
        import psutil
    except ImportError:
        logger.error("Package 'psutil' is missing!")
        return False

    if not check_if_installed("lddtree"):
        logger.error("Tool 'lddtree' is missing (Hint: run `sudo apt install pax-utils`)!")
        return False

    try:
        import fastrand
    except ImportError:
        logger.error("Package 'fastrand' is missing!")
        return False

    try:
        import inotify
    except ImportError:
        logger.error("Package 'inotify' is missing!")
        return False

    return True

def vmx_pt_get_addrn(verbose=True):
    from fcntl import ioctl

    KVMIO = 0xAE
    KVM_VMX_PT_GET_ADDRN = KVMIO << (8) | 0xe9

    try:
        fd = open("/dev/kvm", "wb")
    except:
        logger.error("KVM-PT is not loaded!")
        return 0

    try:
        ret = ioctl(fd, KVM_VMX_PT_GET_ADDRN, 0)
    except IOError:
        logger.warn("Kernel does not support multi-range tracing!")
        ret = 1
    finally:
        fd.close()
    return ret

def vmx_pt_check_addrn(config):

    if config.argument_values["ip3"]:
        ip_ranges = 4
    elif config.argument_values["ip2"]:
        ip_ranges = 3
    elif config.argument_values["ip1"]:
        ip_ranges = 2
    elif config.argument_values["ip0"]:
        ip_ranges = 1
    else:
        ip_ranges = 0

    ret = vmx_pt_get_addrn()

    if ip_ranges > ret:
        logger.error("Attempt to use %d PT range filters but CPU only supports %d!" % (ip_ranges, ret))
        return False
    return True

def check_vmx_pt():
    from fcntl import ioctl

    KVMIO = 0xAE
    KVM_VMX_PT_SUPPORTED = KVMIO << (8) | 0xe4

    try:
        fd = open("/dev/kvm", "wb")
    except:
        logger.error("Unable to access /dev/kvm. Check permissions and ensure KVM is loaded.")
        return False

    try:
        ret = ioctl(fd, KVM_VMX_PT_SUPPORTED, 0)
    except IOError:
        logger.error("VMX_PT is not loaded!")
        return False
    fd.close()

    if ret == 0:
        logger.error("Intel PT is not supported on this CPU!")
        return False

    return True


def check_apple_osk(config):
    if config.argument_values["macOS"]:
        if config.config_values["APPLE-SMC-OSK"] == "":
            logger.error("APPLE SMC OSK is missing in kafl.ini!")
            return False
    return True


def check_apple_ignore_msrs(config):
    if config.argument_values["macOS"]:
        try:
            f = open("/sys/module/kvm/parameters/ignore_msrs")
            if not 'Y' in f.read(1):
                logger.error(
                    "KVM-PT is not properly configured! Please try the following:" \
                    "\n\n\tsudo su\n\techo 1 > /sys/module/kvm/parameters/ignore_msrs\n")
                return False
            else:
                return True
        except:
            pass
        finally:
            f.close()
        logger.error("KVM-PT is not ready?!")
        return False
    return True


def check_kafl_ini(rootdir):
    configfile = rootdir + "kafl.ini"
    if not os.path.exists(configfile):
        logger.error("Could not find kafl.ini. Creating default config at %s" % configfile)
        from common.config import FuzzerConfiguration
        FuzzerConfiguration(configfile,skip_args=True).create_initial_config()
        return False
    return True


def check_qemu_version(config):
    qemu_path = config.config_values["QEMU_KAFL_LOCATION"]
    if not qemu_path or qemu_path == "":
        logger.error("Please set QEMU_KAFL_LOCATION in kafl.ini!")
        return False

    if not os.path.exists(qemu_path):
        logger.error("Could not find QEMU-PT at %s..." % qemu_path)
        return False

    output = ""
    try:
        proc = subprocess.Popen(
                [qemu_path, "-version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE)
        output = str(proc.stdout.readline())
        proc.wait()
    except:
        logger.error("Failed to execute %s...?" % qemu_path)
        return False
    if not ("QEMU-PT" in output and "(kAFL)" in output):
        logger.error("Qemu executable at %s is missing the kAFL patch?" % qemu_path)
        return False
    return True

def check_radamsa_location(config):
    if "radamsa" not in config.argument_values or not config.argument_values["radamsa"]:
        return True

    radamsa_path = config.config_values["RADAMSA_LOCATION"]
    if not radamsa_path or radamsa_path == "":
        logger.error("RADAMSA_LOCATION is not set in kafl.ini!")
        return False

    if not os.path.exists(radamsa_path):
        logger.error("RADAMSA executable does not exist. Try ./install.sh radamsa")
        return False

    return True

def check_cpu_num(config):
    import multiprocessing

    if 'p' not in config.argument_values:
        return True

    max_cpus = int(multiprocessing.cpu_count())
    if int(config.argument_values["p"]) > max_cpus:
        logger.error("Only %d fuzzing processes are supported..." % max_cpus)
        return False
    return True

def self_check(rootdir):
    if not check_if_nativ_lib_compiled(rootdir):
        return False
    if not check_kafl_ini(rootdir):
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
    if not check_radamsa_location(config):
        return False
    if not vmx_pt_check_addrn(config):
        return False
    if not check_cpu_num(config):
        return False
    return True
