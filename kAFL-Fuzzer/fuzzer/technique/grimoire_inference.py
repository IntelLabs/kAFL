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

import re
from collections import OrderedDict

from common.debug import log_grimoire


class GrimoireInference:

    def __init__(self, config, verify_input):
        self.config = config
        self.verify_input = verify_input
        self.generalized_inputs = OrderedDict({tuple(["gap"]): 0})
        self.tokens = OrderedDict({tuple([""]): 0})
        self.strings = []
        self.strings_regex = None
        self.load_strings()

    @staticmethod
    def wordlist_to_regex(words):
        escaped = map(re.escape, words)
        combined = '|'.join(sorted(escaped, key=len, reverse=True))
        return re.compile(combined)

    def load_strings(self):
        if not self.config.argument_values["I"]:
            return

        path = self.config.argument_values["I"]
        strings = []

        for l in open(path):
            if not l.startswith("#"):
                try:
                    s = (l.split("=\"")[1].split("\"\n")[0]).decode("string_escape")
                    if s == "":
                        continue
                    self.tokens[tuple([c for c in s])] = 0
                    strings.append(s)
                except:
                    pass
        self.strings = strings
        self.strings_regex = self.wordlist_to_regex(strings)

    @staticmethod
    def char_class_to_str(name):
        if name == "gap":
            return ""
        else:
            return name

    def generalized_to_string(self, generalized_input):
        return "".join([self.char_class_to_str(char_class) for char_class in generalized_input])

    @staticmethod
    def to_printable_char_class(name):
        if name == "gap":
            return "{}"
        else:
            return name

    @staticmethod
    def trim_generalized(generalized_input):
        ret = []
        before = ""
        for char_class in generalized_input:
            if char_class == before and char_class == "gap":
                pass
            else:
                ret.append(char_class)
            before = char_class
        return ret

    def find_gaps(self, payload, old_node, default_info, find_next_index, split_char):
        index = 0
        while index < len(payload):
            resume_index = find_next_index(payload, index, split_char)
            test_payload = self.generalized_to_string(payload[0:index] + payload[resume_index:])

            if self.verify_input(test_payload, old_node, default_info):
                res = "gap"
                payload[index:resume_index] = [res] * (resume_index - index)

            index = resume_index

        return self.trim_generalized(payload)

    def find_gaps_in_closures(self, payload, old_node, default_info, find_closures, opening_char, closing_char):

        index = 0
        while index < len(payload):
            index, endings = find_closures(payload, index, opening_char, closing_char)

            if len(endings) == 0:
                return payload

            ending = len(payload)
            while endings:
                ending = endings.pop(0)

                test_payload = self.generalized_to_string(payload[0:index] + payload[ending:])

                if self.verify_input(test_payload, old_node, default_info):
                    res = "gap"

                    payload[index:ending] = [res] * (ending - index)

                    break

            index = ending

        return self.trim_generalized(payload)

    def generalize_input(self, payload, old_node, default_info):
        if not self.verify_input(payload, old_node, default_info):
            return None, None

        log_grimoire("generalizing input {} with bytes {}".format(repr(payload), old_node["new_bytes"]))
        generalized_input = [c for c in payload]

        def increment_by_offset(_, index, offset):
            return index + offset

        def find_next_char(l, index, char):
            while index < len(l):
                if l[index] == char:
                    return index + 1

                index += 1

            return index

        def find_closures(l, index, opening_char, closing_char):
            endings = []

            while index < len(l):
                if l[index] == opening_char:
                    break
                index += 1

            start_index = index
            index_ending = len(l) - 1

            while index_ending > start_index:
                if l[index_ending] == closing_char:
                    endings.append(index_ending + 1)
                index_ending -= 1

                index += 1
            return start_index, endings

        generalized_input = self.find_gaps(generalized_input, old_node, default_info, increment_by_offset, 256)
        generalized_input = self.find_gaps(generalized_input, old_node, default_info, increment_by_offset, 128)
        generalized_input = self.find_gaps(generalized_input, old_node, default_info, increment_by_offset, 64)
        generalized_input = self.find_gaps(generalized_input, old_node, default_info, increment_by_offset, 32)
        generalized_input = self.find_gaps(generalized_input, old_node, default_info, increment_by_offset, 1)
        generalized_input = self.find_gaps(generalized_input, old_node, default_info, find_next_char, ".", )
        generalized_input = self.find_gaps(generalized_input, old_node, default_info, find_next_char, ";")
        generalized_input = self.find_gaps(generalized_input, old_node, default_info, find_next_char, ",")
        generalized_input = self.find_gaps(generalized_input, old_node, default_info, find_next_char, "\n")
        generalized_input = self.find_gaps(generalized_input, old_node, default_info, find_next_char, "\r")
        generalized_input = self.find_gaps(generalized_input, old_node, default_info, find_next_char, "#")
        generalized_input = self.find_gaps(generalized_input, old_node, default_info, find_next_char, " ")

        generalized_input = self.find_gaps_in_closures(generalized_input, old_node, default_info, find_closures, "(",
                                                       ")")
        generalized_input = self.find_gaps_in_closures(generalized_input, old_node, default_info, find_closures, "[",
                                                       "]")
        generalized_input = self.find_gaps_in_closures(generalized_input, old_node, default_info, find_closures, "{",
                                                       "}")
        generalized_input = self.find_gaps_in_closures(generalized_input, old_node, default_info, find_closures, "<",
                                                       ">")
        generalized_input = self.find_gaps_in_closures(generalized_input, old_node, default_info, find_closures, "'",
                                                       "'")
        generalized_input = self.find_gaps_in_closures(generalized_input, old_node, default_info, find_closures, "\"",
                                                       "\"")

        generalized_input = self.finalize_generalized(generalized_input)

        if len(generalized_input) > 8192:
            return None, None

        self.add_to_inputs(generalized_input)
        printable_generalized = self.to_printable(generalized_input)
        log_grimoire("final class learnt: {}".format(repr(printable_generalized)))
        log_grimoire("new input: {}".format(repr(self.generalized_to_string(generalized_input))))

        return repr(printable_generalized), generalized_input

    def to_printable(self, generalized_input):
        return "".join([self.to_printable_char_class(char_class) for char_class in generalized_input])

    @staticmethod
    def finalize_generalized(generalized_input):
        return tuple(generalized_input)

    @staticmethod
    def tokenize(generalized_input):
        token = []
        for char_class in generalized_input:
            if char_class != "gap":
                token.append(char_class)
            else:
                if token:
                    yield tuple(token)
                    token = []
        yield tuple(token)

    def add_to_inputs(self, generalized_input):
        assert isinstance(generalized_input, tuple)

        if generalized_input not in self.generalized_inputs:
            self.generalized_inputs[generalized_input] = 0
        self.generalized_inputs[generalized_input] += 1

        if self.generalized_inputs[generalized_input] > 1:
            return

        for token in self.tokenize(generalized_input):
            if len(token) < 2:
                continue
            if token not in self.tokens:
                log_grimoire("adding token {}".format(repr(token)))
                self.tokens[token] = 0
            self.tokens[token] += 1
