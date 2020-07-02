# Copyright 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

import ctypes
import mmh3

from fuzzer.bitmap import GlobalBitmap


class ExecutionResult:

    @staticmethod
    def bitmap_from_bytearray(bitmap, exitreason, performance):
        bitmap_size = len(bitmap)
        c_bitmap = (ctypes.c_uint8 * bitmap_size).from_buffer_copy(bitmap)
        return ExecutionResult(c_bitmap, bitmap_size, exitreason, performance)

    def __init__(self, cbuffer, bitmap_size, exit_reason, performance):
        self.bitmap_size = bitmap_size
        self.cbuffer = cbuffer
        self.lut_applied = False  # By default we assume that the bucket lut has not yet been applied
        self.exit_reason = exit_reason
        self.performance = performance

    def invalidate(self):
        self.cbuffer = None
        return self

    def is_crash(self):
        return self.exit_reason != "regular"

    def is_regular(self):
        return not self.is_crash()

    def is_lut_applied(self):
        return self.lut_applied

    def copy_to_array(self):
        return bytearray(self.cbuffer)

    def hash(self):
        return mmh3.hash(self.cbuffer, signed=False)

    def apply_lut(self):
        assert not self.lut_applied
        GlobalBitmap.apply_lut(self)
        assert self.lut_applied
        return self
