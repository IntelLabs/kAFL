# Copyright (C) 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright (C) 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Grimoire grammar-based mutations (havoc stage)
"""

from common.debug import log_grimoire
from fuzzer.technique.helper import rand

CHOOSE_SUBINPUT = 50
RECURSIVE_REPLACEMENT_DEPTH = [2, 4, 8, 16, 32, 64]


def filter_gap_indices(generalized_input):
    return [index for index in range(len(generalized_input)) if generalized_input[index] == b'']


def find_string_matches(generalized_input, grimoire_inference):
    if grimoire_inference.strings_regex == None:
        return []
    payload = grimoire_inference.generalized_to_string(generalized_input)
    string_matches = [match for match in grimoire_inference.strings_regex.finditer(payload)]

    log_grimoire("{} string matches for {} strings".format(len(string_matches), len(grimoire_inference.strings)))

    return string_matches


def pad_generalized_input(generalized_input):
    if not generalized_input:
        return tuple([b''])
    if not generalized_input[0] == b'':
        generalized_input = tuple([b'']) + generalized_input
    if not generalized_input[-1] == b'':
        generalized_input = generalized_input + tuple([b''])
    return generalized_input


def random_generalized(grimoire_inference):
    rand_generalized = list(grimoire_inference.generalized_inputs.keys())[rand.int(len(grimoire_inference.generalized_inputs))]
    rand_generalized = pad_generalized_input(rand_generalized)

    if rand.int(100) > CHOOSE_SUBINPUT and len(rand_generalized) > 0:
        if rand.int(100) < 50 and len(rand_generalized) > 0:
            gap_indices = filter_gap_indices(rand_generalized)
            min_index, max_index = rand.select(gap_indices), rand.select(gap_indices)
            min_index, max_index = min(min_index, max_index), max(min_index, max_index)
            rand_generalized = rand_generalized[min_index:max_index + 1]
        else:
            random_token = list(grimoire_inference.tokens.keys())[rand.int(len(grimoire_inference.tokens))]
            rand_generalized = pad_generalized_input(random_token)

        assert rand_generalized[0] == b'' and rand_generalized[-1] == b''
    return rand_generalized


def recursive_replacement(generalized_input, grimoire_inference, depth):
    for _ in range(depth):

        if len(generalized_input) >= 64 << 10:
            return generalized_input

        gap_indices = filter_gap_indices(generalized_input)

        if len(gap_indices) == 0:
            return generalized_input

        random_index = rand.select(gap_indices)

        generalized_input = generalized_input[0:random_index] + random_generalized(
            grimoire_inference) + generalized_input[random_index + 1:]

    return generalized_input


def mutate_recursive_replacement(generalized_input, func, grimoire_inference):

    depth = rand.select(RECURSIVE_REPLACEMENT_DEPTH)
    generalized_input = recursive_replacement(generalized_input, grimoire_inference, depth)
    data = grimoire_inference.generalized_to_string(generalized_input)

    func(data, label="grim_recursive")


def mutate_input_extension(generalized_input, func, grimoire_inference):

    rand_generalized = random_generalized(grimoire_inference)

    data = grimoire_inference.generalized_to_string(rand_generalized) + grimoire_inference.generalized_to_string(generalized_input)
    func(data, label="grim_extension")

    data = grimoire_inference.generalized_to_string(generalized_input) + grimoire_inference.generalized_to_string(rand_generalized)
    func(data, label="grim_extension")


def mutate_replace_strings(generalized_input, func, grimoire_inference, string_matches):
    if len(string_matches) == 0:
        return

    payload = grimoire_inference.generalized_to_string(generalized_input)

    match = rand.select(string_matches)
    rand_str = rand.select(grimoire_inference.strings)

    # replace single instance
    data = payload[0:match.start()] + rand_str + payload[match.end():]
    func(data, label="grim_repl_str")

    # replace all instances
    data = payload.replace(payload[match.start():match.end()], rand_str)
    func(data, label="grim_repl_str")


def havoc(generalized_input, func, grimoire_inference, max_iterations, generalized):
    generalized_input = pad_generalized_input(generalized_input)
    assert generalized_input[0] == b'' and generalized_input[-1] == b''

    string_matches = find_string_matches(generalized_input, grimoire_inference)

    for _ in range(max_iterations):
        if generalized:
            mutate_input_extension(generalized_input, func, grimoire_inference)
            mutate_recursive_replacement(generalized_input, func, grimoire_inference)
        mutate_replace_strings(generalized_input, func, grimoire_inference, string_matches)
