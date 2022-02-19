# Copyright 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

import os
import sys
import subprocess
import multiprocessing
from fcntl import ioctl

from kafl_fuzzer.common.logger import logger
from kafl_fuzzer.native import loader as native_loader


def check_if_nativ_lib_compiled():
    return native_loader.test_build()

def check_version():
    if sys.version_info < (3, 6, 0):
        logger.error("This script requires python 3!")
        return False
    return True


def check_packages():

    deps = [
            'msgpack',
            'mmh3',
            'lz4',
            'psutil',
            'fastrand',
            'inotify',
            'pgrep',
            'pygraphviz',
            'toposort',
            ]

    import importlib
    for pkg in deps:
        try:
            importlib.import_module(pkg)
        except (ImportError):
            logger.error("Failed to import package %s - check dependencies!" % pkg)
            return False

    return True

def vmx_pt_get_addrn(verbose=True):

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
    if config.ip3:
        ip_ranges = 4
    elif config.ip2:
        ip_ranges = 3
    elif config.ip1:
        ip_ranges = 2
    elif config.ip0:
        ip_ranges = 1
    else:
        ip_ranges = 0

    ret = vmx_pt_get_addrn()

    if ip_ranges > ret:
        logger.error("Attempt to use %d PT range filters but CPU only supports %d!" % (ip_ranges, ret))
        return False
    return True

def check_vmx_pt():

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

def check_qemu_version(config):
    qemu_path = config.qemu_path

    if not qemu_path or not os.path.exists(qemu_path):
        logger.error("Could not find QEMU at %s..." % qemu_path)
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
    if 'radamsa' not in config or not config.radamsa:
        return True

    radamsa_path = config.radamsa_path

    if not radamsa_path or radamsa_path == "":
        logger.error("Enabling radamsa requires --radamsa-path to be set!")
        return False

    if not os.path.exists(radamsa_path):
        logger.error("Could not find Radamsa in %s. Try ./install.sh radamsa" % radamsa_path)
        return False

    return True

def check_cpu_num(config):

    if 'p' not in config:
        return True

    max_cpus = int(multiprocessing.cpu_count())
    if int(config.p) > max_cpus:
        logger.error("Only %d fuzzing processes are supported..." % max_cpus)
        return False
    return True

def self_check():
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
    if not check_qemu_version(config):
        return False
    if not check_radamsa_location(config):
        return False
    if not vmx_pt_check_addrn(config):
        return False
    if not check_cpu_num(config):
        return False
    return True
