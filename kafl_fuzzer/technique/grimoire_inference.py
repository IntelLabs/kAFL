# Copyright 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Grimoire Grammar Inference (analysis/inference stage)
"""

import re

from collections import OrderedDict
from six.moves import map

from kafl_fuzzer.common import logger


class GrimoireInference:

    def __init__(self, config, verify_input):
        self.config = config
        self.verify_input = verify_input
        self.generalized_inputs = OrderedDict({tuple([b'']): 0})
        self.tokens = OrderedDict({tuple([b'']): 0})
        self.strings = []
        self.strings_regex = None
        self.load_strings()

    @staticmethod
    def wordlist_to_regex(words):
        escaped = list(map(re.escape, words))
        combined = '|'.join(sorted(escaped, key=len, reverse=True))
        return re.compile(combined)

    def load_strings(self):
        if not self.config.argument_values["dict"]:
            return

        path = self.config.argument_values["dict"]
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

    def generalized_to_string(self, generalized_input):
        #print("GeneralizedToString:", repr(generalized_input))
        return b''.join([c for c in generalized_input if c != b''])

        #payload = b''
        #for c in generalized_input:
        #    assert(isinstance(c, bytes)), print("Invalid input element:", type(c), repr(generalized_input))
        #    payload += c
        #return payload


    @staticmethod
    def trim_generalized(generalized_input):
        ret = []
        before = b''
        for char_class in generalized_input:
            if char_class == before and char_class == b'':
                pass
            else:
                ret.append(char_class)
            before = char_class
        return ret

    def find_gaps(self, payload, old_node, find_next_index, split_char):
        index = 0
        while index < len(payload):
            resume_index = find_next_index(payload, index, split_char)
            test_payload = self.generalized_to_string(payload[0:index] + payload[resume_index:])

            if self.verify_input(test_payload, old_node):
                res = b''
                payload[index:resume_index] = [res] * (resume_index - index)

            index = resume_index

        return self.trim_generalized(payload)

    def find_gaps_in_closures(self, payload, old_node, find_closures, opening_char, closing_char):

        index = 0
        while index < len(payload):
            index, endings = find_closures(payload, index, opening_char, closing_char)

            if len(endings) == 0:
                return payload

            ending = len(payload)
            while endings:
                ending = endings.pop(0)

                test_payload = self.generalized_to_string(payload[0:index] + payload[ending:])

                if self.verify_input(test_payload, old_node):
                    res = b''

                    payload[index:ending] = [res] * (ending - index)

                    break

            index = ending

        return self.trim_generalized(payload)

    def generalize_input(self, payload, old_node):
        if not self.verify_input(payload, old_node):
            return None

        #logger.debug("Grimoire: Generalizing input {} with bytes {}".format(repr(payload), old_node["new_bytes"]))
        generalized_input = [bytes([c]) for c in payload]

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

        generalized_input = self.find_gaps(generalized_input, old_node, increment_by_offset, 256)
        generalized_input = self.find_gaps(generalized_input, old_node, increment_by_offset, 128)
        generalized_input = self.find_gaps(generalized_input, old_node, increment_by_offset, 64)
        generalized_input = self.find_gaps(generalized_input, old_node, increment_by_offset, 32)
        generalized_input = self.find_gaps(generalized_input, old_node, increment_by_offset, 1)
        generalized_input = self.find_gaps(generalized_input, old_node, find_next_char, b".", )
        generalized_input = self.find_gaps(generalized_input, old_node, find_next_char, b";")
        generalized_input = self.find_gaps(generalized_input, old_node, find_next_char, b",")
        generalized_input = self.find_gaps(generalized_input, old_node, find_next_char, b"\n")
        generalized_input = self.find_gaps(generalized_input, old_node, find_next_char, b"\r")
        generalized_input = self.find_gaps(generalized_input, old_node, find_next_char, b"#")
        generalized_input = self.find_gaps(generalized_input, old_node, find_next_char, b" ")

        generalized_input = self.find_gaps_in_closures(generalized_input, old_node, find_closures, b"(", b")")
        generalized_input = self.find_gaps_in_closures(generalized_input, old_node, find_closures, b"[", b"]")
        generalized_input = self.find_gaps_in_closures(generalized_input, old_node, find_closures, b"{", b"}")
        generalized_input = self.find_gaps_in_closures(generalized_input, old_node, find_closures, b"<", b">")
        generalized_input = self.find_gaps_in_closures(generalized_input, old_node, find_closures, b"'", b"'")
        generalized_input = self.find_gaps_in_closures(generalized_input, old_node, find_closures, b'"', b'"')

        generalized_input = self.finalize_generalized(generalized_input)

        if len(generalized_input) > 8192:
            return None

        self.add_to_inputs(generalized_input)
        #logger.debug("Grimoire: new input: {}".format(repr(self.generalized_to_string(generalized_input))))

        return generalized_input

    @staticmethod
    def finalize_generalized(generalized_input):
        return tuple(generalized_input)

    @staticmethod
    def tokenize(generalized_input):
        token = []
        for char_class in generalized_input:
            if char_class != b'':
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
                #logger.debug(Grimoire: "adding token {}".format(repr(token)))
                self.tokens[token] = 0
            self.tokens[token] += 1
