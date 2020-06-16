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
