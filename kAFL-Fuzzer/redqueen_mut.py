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

import array
import sys

from fuzzer.technique.redqueen import parser
from fuzzer.technique.redqueen.mod import RedqueenInfoGatherer

info = RedqueenInfoGatherer()

info.collected_infos_path = sys.argv[1]
info.num_alternative_inputs = 2

info.get_proposals()
print("got %d mutations on %s" % (info.get_num_mutations(), sys.argv[1]))

orig_input = open(sys.argv[1] + "/input_2.bin", "rb").read()
print("Mutating : %s" % repr(orig_input))


def fake_execute(str, a, b):
    print("executing %s" % repr(str))


info.verbose = True
default_info = {}
info.run_mutate_redqueen(array.array("B", orig_input), fake_execute, default_info)
