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

import glob

from common.config import FuzzerConfiguration
from fuzzer.technique.havoc_handler import *


def load_dict(file_name):
    f = open(file_name)
    dict_entries = []
    for line in f:
        if not line.startswith("#"):
            try:
                dict_entries.append((line.split("=\"")[1].split("\"\n")[0]).decode("string_escape"))
            except:
                pass
    f.close()
    return dict_entries


def init_havoc(config):
    global location_corpus
    if config.argument_values["I"]:
        set_dict(load_dict(FuzzerConfiguration().argument_values["I"]))
        append_handler(havoc_dict)
        append_handler(havoc_dict)

    location_corpus = config.argument_values['work_dir'] + "/corpus/"


def havoc_range(perf_score):
    max_iterations = int(perf_score * 2.5)

    if max_iterations < AFL_HAVOC_MIN:
        max_iterations = AFL_HAVOC_MIN

    return max_iterations


def mutate_seq_havoc_array(data, func, default_info, max_iterations, stacked=True, resize=False, files_to_splice=None):
    reseed()
    if resize:
        copy = array('B', data.tostring() + data.tostring())
    else:
        copy = array('B', data.tostring())

    cnt = 0
    for i in range(max_iterations):
        # if resize:
        #    copy = array('B', data.tostring() + data.tostring())
        # else:
        copy = array('B', data.tostring())

        value = RAND(AFL_HAVOC_STACK_POW2)

        for j in range(1 << (1 + value)):
            handler = havoc_handler[RAND(len(havoc_handler))]
            # if not stacked:
            #    if resize:
            #        copy = array('B', data.tostring() + data.tostring())
            #    else:
            #        copy = array('B', data.tostring())
            copy = handler(copy)
            if len(copy) >= 64 << 10:
                copy = copy[:(64 << 10)]
            # cnt += 1
            # if cnt >= max_iterations:
            #    return
        func(copy.tostring(), default_info)
    pass


def mutate_seq_splice_array(data, func, default_info, max_iterations, stacked=True, resize=False):
    files = glob.glob(location_corpus + "/*/payload_*")
    random.shuffle(files)
    mutate_seq_havoc_array(havoc_splicing(data, files), func, default_info, max_iterations, stacked=stacked,
                           resize=resize)
