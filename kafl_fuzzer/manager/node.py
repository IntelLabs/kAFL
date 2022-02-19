# Copyright 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Fuzz inputs are managed as nodes in a queue. Any persistent metadata is stored here as node attributes.
"""

import lz4.frame
import mmh3
import msgpack

from kafl_fuzzer.common.util import read_binary_file, atomic_write


class QueueNode:
    NextID = 1

    def __init__(self, config, payload, bitmap, node_struct, write=True):
        self.node_struct = node_struct
        self.busy = False
        self.workdir = config.work_dir

        self.set_id(QueueNode.NextID, write=False)
        QueueNode.NextID += 1

        self.set_payload(payload, write=write)
        # store individual bitmaps only in debug mode
        if bitmap and config.debug:
            self.write_bitmap(bitmap)

        self.node_struct["attention_execs"] = 0
        self.node_struct["attention_secs"] = 0
        self.set_state("initial", write=False)

    @staticmethod
    def get_metadata(workdir, node_id):
        return msgpack.unpackb(read_binary_file(QueueNode.__get_metadata_filename(workdir, node_id)), strict_map_key=False)

    @staticmethod
    def get_payload(workdir, node_struct):
        return read_binary_file(QueueNode.__get_payload_filename(workdir, node_struct['info']['exit_reason'], node_struct['id']))

    @staticmethod
    def __get_payload_filename(workdir, exit_reason, node_id):
        return "%s/corpus/%s/payload_%05d" % (workdir, exit_reason, node_id)

    @staticmethod
    def __get_metadata_filename(workdir, node_id):
        return "%s/metadata/node_%05d" % (workdir, node_id)

    def update_file(self, write=True):
        if write:
            node_path = QueueNode.__get_metadata_filename(self.workdir, self.get_id())
            atomic_write(node_path, msgpack.packb(self.node_struct))

    def write_bitmap(self, bitmap):
        bitmap_path = "%s/bitmaps/payload_%05d.lz4" % (self.workdir, self.get_id())
        atomic_write(bitmap_path, lz4.frame.compress(bitmap))

    # will be used both for the final update and the intermediate update in the statelogic. Needs to work in both occasions!
    # That means it needs to be able to apply an update to another update as well as the final meta data
    # This function must leave new_data unchanged, but may change old_data
    @staticmethod
    def apply_metadata_update(old_data, new_data):
        new_data = new_data.copy()  # if we remove keys deeper than attention_execs and attention_secs, we need a deep copy

        for key in [
                "attention_execs",
                "attention_secs",
                "state_time_initial",
                "state_time_redqueen",
                "state_time_grimoire",
                "state_time_grimoire_inference",
                "state_time_havoc",
                "state_time_splice",
                "state_time_radamsa"
                ]:

            old_data[key] = old_data.get(key, 0) + new_data[key]
            del new_data[key]

        old_data.update(new_data)
        return old_data

    def update_metadata(self, delta, write=True):
        self.node_struct = QueueNode.apply_metadata_update(self.node_struct, delta)
        self.update_file(write=write)

    def set_payload(self, payload, write=True):
        self.set_payload_len(len(payload), write=False)
        atomic_write(QueueNode.__get_payload_filename(self.workdir, self.get_exit_reason(), self.get_id()), payload)

    def get_payload_len(self):
        return self.node_struct["payload_len"]

    def set_payload_len(self, val, write=True):
        self.node_struct["payload_len"] = val
        self.update_file(write)

    def get_id(self):
        return self.node_struct["id"]

    def set_id(self, val, write=True):
        self.node_struct["id"] = val
        self.update_file(write)

    def get_new_bytes(self):
        return self.node_struct["new_bytes"]

    def set_new_bytes(self, val, write=True):
        self.node_struct["new_bytes"] = val
        self.update_file(write)

    def get_new_bits(self):
        return self.node_struct["new_bits"]

    def clear_fav_bits(self, write=True):
        self.node_struct["fav_bits"] = {}
        self.update_file(write)

    def get_fav_bits(self):
        return self.node_struct["fav_bits"]

    def add_fav_bit(self, index, write=True):
        self.node_struct["fav_bits"][index] = 0
        self.update_file(write)

    def remove_fav_bit(self, index, write=True):
        assert index in self.node_struct["fav_bits"]
        self.node_struct["fav_bits"].pop(index)
        self.update_file(write)

    def set_new_bits(self, val, write=True):
        self.node_struct["new_bits"] = val
        self.update_file(write)

    def get_level(self):
        return self.node_struct["level"]

    def set_level(self, val, write=True):
        self.node_struct["level"] = val
        self.update_file(write)

    def is_favorite(self):
        return len(self.node_struct["fav_bits"]) > 0

    def get_parent_id(self):
        return self.node_struct["info"]["parent"]

    def get_timestamp(self):
        return self.node_struct["info"]["time"]

    def get_method(self):
        return self.node_struct["info"]["method"]

    def get_initial_performance(self):
        return self.node_struct["info"]["performance"]

    def get_performance(self):
        return self.node_struct["performance"]

    def set_performance(self, val, write=True):
        self.node_struct["performance"] = val
        self.update_file(write)

    def get_state(self):
        return self.node_struct["state"]["name"]

    def set_state(self, val, write=True):
        self.node_struct["state"]["name"] = val
        self.update_file(write)

    def get_exit_reason(self):
        return self.node_struct["info"]["exit_reason"]

    def set_exit_reason(self, val, write=True):
        self.node_struct["info"]["exit_reason"] = val
        self.update_file(write)

    def get_fav_factor(self):
        return self.node_struct["fav_factor"]

    def set_score(self, val):
        self.node_struct["score"] = val

    def get_score(self):
        return self.node_struct["score"]

    def set_fav_factor(self, val, write=True):
        self.node_struct["fav_factor"] = val
        self.update_file(write)

    def set_free(self):
        self.busy = False

    def set_busy(self):
        self.busy = True

    def is_busy(self):
        return self.busy
