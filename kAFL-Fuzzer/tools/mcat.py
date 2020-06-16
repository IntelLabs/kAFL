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

# !/usr/bin/env python2
import msgpack
import os
import sys
from pprint import pprint

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)) + "/../")
from common.util import read_binary_file

for arg in sys.argv[1:]:
    pprint(msgpack.unpackb(read_binary_file(arg)))
