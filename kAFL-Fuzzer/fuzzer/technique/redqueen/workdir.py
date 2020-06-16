# Copyright (C) 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright (C) 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Redqueen workdir/Qemu interface
"""

import os
import shutil


class RedqueenWorkdir:
    def __init__(self, qemu_id, config):
        self.base_path = config.argument_values['work_dir'] + "/redqueen_workdir_" + str(qemu_id)

    def init_dir(self):
        if os.path.exists(self.base_path):
            shutil.rmtree(self.base_path)
        os.makedirs(self.base_path)

    def redqueen(self):
        return self.base_path + "/redqueen_results.txt"

    def patches(self):
        return self.base_path + "/redqueen_patches.txt"

    def whitelist(self):
        return self.base_path + "/breakpoint_white.txt"

    def blacklist(self):
        return self.base_path + "/breakpoint_black.txt"

    def code_dump(self):
        return self.base_path + "/target_code_dump.img"
