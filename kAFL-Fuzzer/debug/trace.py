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



class TraceParser:
    def __init__(self, config):
        self.targets = set()
        self.input_to_new_targets = {}
        self.config = config

    def parse_and_add_trace(self, input, trace_path):
        with open(trace_path) as f:
            self.input_to_new_targets[input] = []
            for line in f.readlines():
                target = int(line.split(",")[1], 16)
                if target not in self.targets:
                    self.input_to_new_targets[input].append(target)
                    self.targets.add(target)
