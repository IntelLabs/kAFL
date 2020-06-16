# Copyright (C) 2020 Intel Corporation
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Helper functions for kAFL tests
"""

def ham_weight(x):
    _x = bytearray(x)
    weight = 0
    for byte in _x:
        weight += bin(byte).count("1")
    return weight

def ham_distance(a,b):
    return ham_weight(bytes(x ^ y for (x, y) in zip(a, b)))

