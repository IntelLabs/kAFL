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

import zlib

import mmh3
import msgpack

from common.config import FuzzerConfiguration
from common.util import read_binary_file, atomic_write


class QueueNode:
    NextID = 1

    def __init__(self, payload, bitmap, node_struct, write=True):
        self.node_struct = node_struct

        self.set_id(QueueNode.NextID, write=False)

        QueueNode.NextID += 1

        self.set_payload(payload, write=False)
        self.set_bitmap(bitmap)
        self.update_file(write)

    @staticmethod
    def get_metadata(id):
        return msgpack.unpackb(read_binary_file(QueueNode.__get_metadata_filename(id)))

    @staticmethod
    def get_payload(exitreason, id):
        return read_binary_file(QueueNode.__get_payload_filename(exitreason, id))

    def __get_bitmap_filename(self):
        workdir = FuzzerConfiguration().argument_values['work_dir']
        filename = "/bitmaps/payload_%05d.gzip" % (self.get_id())
        return workdir + filename

    @staticmethod
    def __get_payload_filename(exit_reason, id):
        workdir = FuzzerConfiguration().argument_values['work_dir']
        filename = "/corpus/%s/payload_%05d" % (exit_reason, id)
        return workdir + filename

    @staticmethod
    def __get_metadata_filename(id):
        workdir = FuzzerConfiguration().argument_values['work_dir']
        return workdir + "/metadata/node_%05d" % id

    def update_file(self, write=True):
        if write:
            self.write_metadata()
            self.dirty = False
        else:
            self.dirty = True

    def set_bitmap(self, bitmap):
        atomic_write(self.__get_bitmap_filename(), zlib.compress(bitmap))

    def get_bitmap(self):
        return zlib.decompress(read_binary_file(self.__get_bitmap_filename()))

    def write_metadata(self):
        return atomic_write(QueueNode.__get_metadata_filename(self.get_id()), msgpack.packb(self.node_struct))

    def load_metadata(self):
        QueueNode.get_metadata(self.id)

    @staticmethod
    # will be used both for the final update and the intermediate update in the statelogic. Needs to work in both occasions!
    # That means it needs to be able to apply an update to another update as well as the final meta data
    # This function must leave new_data unchanged, but may change old_data
    def apply_metadata_update(old_data, new_data):
        new_data = new_data.copy()  # if we remove keys deeper than attention_execs and attention_secs, we need a deep copy
        old_data["attention_execs"] = old_data.get("attention_execs", 0) + new_data["attention_execs"]
        old_data["attention_secs"] = old_data.get("attention_secs", 0) + new_data["attention_secs"]

        for key in ["state_time_initial", "state_time_havoc", "state_time_grimoire", "state_time_grimoire_inference",
                    "state_time_redqueen"]:
            old_data[key] = old_data.get(key, 0) + new_data[key]
            del new_data[key]

        del new_data["attention_execs"]
        del new_data["attention_secs"]
        old_data.update(new_data)
        return old_data

    def update_metadata(self, delta, write=True):
        self.node_struct = QueueNode.apply_metadata_update(self.node_struct, delta)
        self.update_file(write)

    def set_payload(self, payload, write=True):
        self.set_payload_len(len(payload), write=False)
        self.set_payload_hash(mmh3.hash(payload), write)
        atomic_write(QueueNode.__get_payload_filename(self.get_exit_reason(), self.get_id()), payload)

    def load_payload(self):
        QueueNode.get_payload(self.get_exit_reason(), self.get_id())

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

    def get_payload_hash(self):
        return self.node_struct["payload_hash"]

    def set_payload_hash(self, val, write=True):
        self.node_struct["payload_hash"] = val
        self.update_file(write)

    def get_new_byte_count(self):
        return self.node_struct["new_byte_count"]

    def set_new_byte_count(self, val, write=True):
        self.node_struct["new_byte_count"] = val
        self.update_file(write)

    def get_new_bit_count(self):
        return self.node_struct["new_bit_count"]

    def set_new_bit_count(self, val, write=True):
        self.node_struct["new_bit_count"] = val
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

    def get_favorite(self):
        return len(self.node_struct["fav_bits"]) > 0

    def get_performance(self):
        return self.node_struct["info"]["performance"]

    def set_performance(self, val, write=True):
        self.node_struct["info"]["performance"] = val
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

    def set_fav_factor(self, val, write=True):
        self.node_struct["fav_factor"] = val
        self.update_file(write)
