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


def MOVE_CURSOR_DOWN(num):
    return "\033[" + str(num) + "B"


def MOVE_CURSOR_LEFT(num):
    return "\033[" + str(num) + "C"


def MOVE_CURSOR_RIGHT(num):
    return "\033[" + str(num) + "D"


HLINE =  chr(0x2500)
VLINE =  chr(0x2502)
VLLINE = chr(0x2524)
VRLINE = chr(0x251c)
LBEDGE = chr(0x2514)
RBEDGE = chr(0x2518)
HULINE = chr(0x2534)
HDLINE = chr(0x252c)
LTEDGE = chr(0x250c)
RTEDGE = chr(0x2510)

INFO_PREFIX =     "[INFO]     "
WARNING_PREFIX =  "[WARNING]  "
CRITICAL_PREFIX = "[CRITICAL] "
ERROR_PREFIX =    "[ERROR]    "
