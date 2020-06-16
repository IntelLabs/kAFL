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


class HashPatcher:
    def __init__(self):
        self.patched = set()
        self.blacklisted = set()

    def add_hash_candidate(self, mut):
        if mut.addr in self.blacklisted or mut.addr in self.patched:
            return
        self.patched.add(mut.addr)
        self.apply_patches()

    def blacklist_hash_candidate(self, addr):
        self.blacklisted.add(addr)
        if addr in self.patched:
            self.patched.remove(addr)
            self.apply_patches()

    def apply_patches(self):
        with open("/tmp/redqueen_whitelist", "w") as w:
            with open("/tmp/rq_patches", "w") as f:
                for addr in self.patched:
                    hexaddr = hex(addr).rstrip("L").lstrip("0x")
                    if hexaddr:
                        w.write(hexaddr + "\n")
                        f.write(hexaddr + "\n")
