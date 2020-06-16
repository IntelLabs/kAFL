# Copyright (C) 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright (C) 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
I wonder what this does?
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
