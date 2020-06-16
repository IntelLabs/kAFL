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

from common.debug import log_grimoire
from fuzzer.technique.helper import RAND

CHOOSE_SUBINPUT = 50
RECURSIVE_REPLACEMENT_DEPTH = [2, 4, 8, 16, 32, 64]


def filter_gap_indices(generalized_input):
    return [index for index in xrange(len(generalized_input)) if generalized_input[index] == "gap"]


def find_string_matches(generalized_input, grimoire_inference):
    payload = grimoire_inference.generalized_to_string(generalized_input)
    string_matches = [match for match in grimoire_inference.strings_regex.finditer(payload)]

    log_grimoire("{} string matches for {} strings".format(len(string_matches), len(grimoire_inference.strings)))

    return string_matches


def pad_generalized_input(generalized_input):
    if not generalized_input:
        return tuple(["gap"])
    if not generalized_input[0] == "gap":
        generalized_input = tuple(["gap"]) + generalized_input
    if not generalized_input[-1] == "gap":
        generalized_input = generalized_input + tuple(["gap"])
    return generalized_input


def random_generalized(grimoire_inference):
    rand_generalized = grimoire_inference.generalized_inputs.keys()[RAND(len(grimoire_inference.generalized_inputs))]
    rand_generalized = pad_generalized_input(rand_generalized)

    if RAND(100) > CHOOSE_SUBINPUT and len(rand_generalized) > 0:
        if RAND(100) < 50 and len(rand_generalized) > 0:
            gap_indices = filter_gap_indices(rand_generalized)
            min_index, max_index = gap_indices[RAND(len(gap_indices))], gap_indices[
                RAND(len(gap_indices))]
            min_index, max_index = min(min_index, max_index), max(min_index, max_index)
            rand_generalized = rand_generalized[min_index:max_index + 1]
        else:
            random_token = grimoire_inference.tokens.keys()[RAND(len(grimoire_inference.tokens))]
            rand_generalized = pad_generalized_input(random_token)

        assert rand_generalized[0] == "gap" and rand_generalized[-1] == "gap"
    return rand_generalized


def recursive_replacement(generalized_input, grimoire_inference, depth):
    for _ in xrange(depth):

        if len(generalized_input) >= 64 << 10:
            return generalized_input

        gap_indices = filter_gap_indices(generalized_input)

        if len(gap_indices) == 0:
            return generalized_input

        random_index = gap_indices[RAND(len(gap_indices))]

        generalized_input = generalized_input[0:random_index] + random_generalized(
            grimoire_inference) + generalized_input[random_index + 1:]

    return generalized_input


def mutate_recursive_replacement(generalized_input, func, default_info, grimoire_inference):
    default_info["method"] = "grimoire_recursive_replacement"

    depth = RECURSIVE_REPLACEMENT_DEPTH[RAND(len(RECURSIVE_REPLACEMENT_DEPTH))]
    generalized_input = recursive_replacement(generalized_input, grimoire_inference, depth)
    data = grimoire_inference.generalized_to_string(generalized_input)

    func(data, default_info)


def mutate_input_extension(generalized_input, func, default_info, grimoire_inference):
    default_info["method"] = "grimoire_input_extension"

    rand_generalized = random_generalized(grimoire_inference)

    data = grimoire_inference.generalized_to_string(rand_generalized) + grimoire_inference.generalized_to_string(
        generalized_input)
    func(data, default_info)

    data = grimoire_inference.generalized_to_string(generalized_input) + grimoire_inference.generalized_to_string(
        rand_generalized)
    func(data, default_info)


def mutate_replace_strings(generalized_input, func, default_info, grimoire_inference, string_matches):
    if len(string_matches) == 0:
        return

    default_info["method"] = "grimoire_replace_strings"

    payload = grimoire_inference.generalized_to_string(generalized_input)

    match = string_matches[RAND((len(string_matches)))]
    rand_str = grimoire_inference.strings[RAND(len(grimoire_inference.strings))]

    # replace single instance
    data = payload[0:match.start()] + rand_str + payload[match.end():]
    func(data, default_info)

    # replace all instances
    data = payload.replace(payload[match.start():match.end()], rand_str)
    func(data, default_info)


def havoc(generalized_input, func, default_info, grimoire_inference, max_iterations, generalized):
    generalized_input = pad_generalized_input(generalized_input)
    assert generalized_input[0] == "gap" and generalized_input[-1] == "gap"

    string_matches = find_string_matches(generalized_input, grimoire_inference)

    for _ in xrange(max_iterations):
        if generalized:
            mutate_input_extension(generalized_input, func, default_info, grimoire_inference)
            mutate_recursive_replacement(generalized_input, func, default_info, grimoire_inference)
        mutate_replace_strings(generalized_input, func, default_info, grimoire_inference, string_matches)
