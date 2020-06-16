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

import glob
import shutil
import time


def se_id(path):
    return int(path.split("/")[-1].split("_")[-1])


def delete(num):
    se_folders = glob.glob('/tmp/redqueen_workdir_' + str(num) + '/se_*')
    se_folders = sorted(se_folders, key=se_id)
    while len(se_folders) > 100:
        path = se_folders.pop(0)
        print("del", path)
        shutil.rmtree(path)


while True:
    for i in range(12):
        delete(i)
    time.sleep(3 * 60)  # 3 minutes
