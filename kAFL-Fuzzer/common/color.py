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

HEADER = '\033[95m'
OKBLUE = '\033[94m'
OKGREEN = '\033[92m'
WARNING = '\033[0;33m'
FAIL = '\033[91m'
ENDC = '\033[0m'
CLRSCR = '\x1b[1;1H'
REALCLRSCR = '\x1b[2J'
BOLD = '\033[1m'
FLUSH_LINE = '\r\x1b[K'


def MOVE_CURSOR_UP(num):
    return "\033[" + str(num) + "A"


def MOVE_CURSOR_DOWN(num):
    return "\033[" + str(num) + "B"


def MOVE_CURSOR_LEFT(num):
    return "\033[" + str(num) + "C"


def MOVE_CURSOR_RIGHT(num):
    return "\033[" + str(num) + "D"


HLINE = unichr(0x2500)
VLINE = unichr(0x2502)
VLLINE = unichr(0x2524)
VRLINE = unichr(0x251c)
LBEDGE = unichr(0x2514)
RBEDGE = unichr(0x2518)
HULINE = unichr(0x2534)
HDLINE = unichr(0x252c)
LTEDGE = unichr(0x250c)
RTEDGE = unichr(0x2510)

INFO_PREFIX = "[INFO]    "
ERROR_PREFIX = "[ERROR]   "
WARNING_PREFIX = "[WARNING] "
