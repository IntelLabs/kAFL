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

import multiprocessing
import signal
import time

from common.config import FuzzerConfiguration
from common.debug import enable_logging
from common.self_check import post_self_check
from common.util import prepare_working_dir, print_fail, ask_for_permission, print_warning, copy_seed_files
from process.master import MasterProcess
from process.slave import slave_loader


def start():
    config = FuzzerConfiguration()

    if not post_self_check(config):
        return -1

    if config.argument_values['v']:
        enable_logging(config.argument_values["work_dir"])

    num_processes = config.argument_values['p']

    if not config.argument_values['Purge']:
        if ask_for_permission("PURGE", " to wipe old workspace:"):
            print_warning("Wiping old workspace...")
            time.sleep(2)
        else:
            print_fail("Aborting...")
            return 0

    prepare_working_dir(config.argument_values['work_dir'])

    if not copy_seed_files(config.argument_values['work_dir'], config.argument_values['seed_dir']):
        print_fail("Seed directory is empty...")
        return 1

    master = MasterProcess(config)

    slaves = []
    for i in range(num_processes):
        print
        "fuzzing process {}".format(i)
        slaves.append(multiprocessing.Process(name='SLAVE' + str(i), target=slave_loader, args=(i,)))
        slaves[i].start()

    try:
        master.loop()
    except KeyboardInterrupt:
        pass

    signal.signal(signal.SIGINT, signal.SIG_IGN)

    counter = 0
    # print_pre_exit_msg(counter, clrscr=True)
    for slave in slaves:
        while True:
            counter += 1
            # print_pre_exit_msg(counter)
            slave.join(timeout=0.25)
            if not slave.is_alive():
                break
    # print_exit_msg()
    return 0
