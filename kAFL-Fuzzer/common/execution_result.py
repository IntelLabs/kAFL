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

    def is_lut_applied(self):
        return self.lut_applied

    def copy_to_array(self):
        return bytearray(self.cbuffer)

    def hash(self):
        return mmh3.hash(self.cbuffer)

    def apply_lut(self):
        assert not self.lut_applied
        GlobalBitmap.apply_lut(self)
        assert self.lut_applied
        return self
