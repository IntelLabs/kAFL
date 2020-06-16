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

def mutate_seq_debug_array(data, func, skip_null=False, kafl_state=None):
    kafl_state["technique"] = "DEBUG"
    for i in range(len(data) * 0xff):
        # tmp = data[i/0xff]
        # data[i/0xff] = (i % 0xff)
        func(data.tostring())
        # data[i/0xff] = tmp
