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

# Wrapper APIs for abstracting + encapsulating some sub-components

import os

import random
import fastrand

class MpackWrapper:

    def pack(self):

    def unpack(self):


class RandomWrapper:

    def reseed(self):
        random.seed(os.urandom(32))
        for _ in range(random.randint(0,1024)): fastrand.pcg32()
    
    def bytes(self, num):
        return bytes([rand.int(256) for _ in range(num)])
    
    # return integer N := 0 <= n < limit
    # Intended semantics:
    #   if rand.int(100) < 50 # execute with p(0.5)
    #   if rand.int(2)        # execute with p(0.5)
    # a[rand.int(len(a)) = 5  # never out of bounds
    def int(self, limit):
        if limit == 0:
            return 0
        return fastrand.pcg32bounded(limit)
    
    def select(self, arg):
        return arg[rand.int(len(arg))]
    
    def shuffle(self, arg):
        return random.shuffle(arg)

pack = MpackWrapper()
rand = RandomWrapper()
