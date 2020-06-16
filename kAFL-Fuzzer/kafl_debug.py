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

import os
import sys

import common.color
from common.self_check import self_check


def main():
    f = open(os.path.dirname(sys.argv[0]) + "/help.txt")
    for line in f:
        print(line.replace("\n", ""))
    f.close()

    print("<< " + common.color.BOLD + common.color.OKGREEN + sys.argv[
        0] + ": kAFL Agent Debugger " + common.color.ENDC + ">>\n")

    if not self_check():
        return 1

    from debug.core import start
    return start()


if __name__ == "__main__":
    main()
