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
import time

from common.config import InfoConfiguration
from common.debug import log_info, enable_logging
from common.qemu import qemu
from common.self_check import post_self_check


def start():
    config = InfoConfiguration()

    if not post_self_check(config):
        return -1

    if config.argument_values['v']:
        enable_logging(config.argument_values["work_dir"])

    log_info("Dumping target addresses...")
    if os.path.exists("/tmp/kAFL_info.txt"):
        os.remove("/tmp/kAFL_info.txt")
    q = qemu(0, config)
    q.start()
    q.__del__()
    try:
        for line in open("/tmp/kAFL_info.txt"):
            print
            line,
        os.remove("/tmp/kAFL_info.txt")
    except:
        pass
    return 0
