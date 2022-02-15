# Copyright 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

HPRINTF =    '\033[95m'
OKBLUE =     '\033[94m'
OKGREEN =    '\033[92m'
WARNING =    '\033[0;33m'
FAIL =       '\033[91m'
ENDC =       '\033[0m'
CLRSCR =     '\x1b[1;1H'
REALCLRSCR = '\x1b[2J'
BOLD =       '\033[1m'
FLUSH_LINE = '\r\x1b[K'


def MOVE_CURSOR_UP(num):
    return "\033[" + str(num) + "A"
