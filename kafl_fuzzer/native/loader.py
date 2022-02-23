# Copyright (C) 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright (C) 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later


"""
Helper for loading C extension
"""

import glob
import inspect
import os
import subprocess

from kafl_fuzzer.common.logger import logger
import kafl_fuzzer.native as native_pkg


def test_build():
    native_path = os.path.dirname(inspect.getfile(native_pkg))
    bitmap_paths = glob.glob(native_path + "/bitmap*so")

    if len(bitmap_paths) < 1:
        logger.warn("Attempting to build native/bitmap.so ...")

        p = subprocess.Popen(("make -C " + native_path).split(" "),
                             stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE)

        if p.wait() != 0:
            logger.error("Build failed, please check..")
            return False

    bitmap_paths = glob.glob(native_path + "/bitmap*so")
    assert len(bitmap_paths) > 0, "Failed to resolve native bitmap.so library."
    return True

def bitmap_path():
    native_path = os.path.dirname(inspect.getfile(native_pkg))
    bitmap_paths = glob.glob(native_path + "/bitmap*so")
    assert len(bitmap_paths) > 0, "Failed to resolve native bitmap.so library."
    return bitmap_paths[0]

#bitmap_native_so = None
#
#if not bitmap_native_so:
#    bitmap_native_so = load_native()

