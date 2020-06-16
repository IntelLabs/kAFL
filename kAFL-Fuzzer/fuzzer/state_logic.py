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

import random
import time
from array import array

import fuzzer.technique.arithmetic as arithmetic
import fuzzer.technique.bitflip as bitflip
import fuzzer.technique.grimoire_mutations as grimoire
import fuzzer.technique.havoc as havoc
import fuzzer.technique.interesting_values as interesting_values
from common.debug import log_grimoire
from common.safe_syscall import safe_print
from fuzzer.node import QueueNode
from fuzzer.technique.grimoire_inference import GrimoireInference
from fuzzer.technique.redqueen.colorize import ColorizerStrategy
from fuzzer.technique.redqueen.mod import RedqueenInfoGatherer
from fuzzer.technique.redqueen.workdir import RedqueenWorkdir
from fuzzer.technique.trim import perform_trim, perform_center_trim


class FuzzingStateLogic:
    HAVOC_MULTIPLIER = 0.5
    RADAMSA_DIV = 10
    COLORIZATION_COUNT = 1
    COLORIZATION_STEPS = 1500
    COLORIZATION_TIMEOUT = 5

    def __init__(self, slave, config):
        self.slave = slave
        self.config = config
        self.num_findings_in_havoc_stage = 0
        self.grimoire = GrimoireInference(config, self.slave.validate_bytes)
        havoc.init_havoc(config)

        self.stage_info_start_time = None
        self.stage_info_execs = None
        self.attention_secs_start = None
        self.attention_execs_start = None

    def __calc_initial_effector_map(self, payload):
        limiter_map = array("B", (1 for _ in xrange(len(payload))))
        if self.config.argument_values['i']:
            for ignores in self.config.argument_values['i']:
                # log_slave("Ignore-range 0: " + str(ignores[0]) + " " + str(min(ignores[0], len(payload))))
                # log_slave("Ignore-range 1: " + str(ignores[1]) + " " + str(min(ignores[1], len(payload))))
                for i in xrange(min(ignores[0], len(payload)), min(ignores[1], len(payload))):
                    limiter_map[i] = 0

        return limiter_map

    def process(self, payload, metadata):
        start_time = time.time()
        update = {}
        while not update or time.time() - start_time < 3:  # keep working each input until at least one seconds passed
            if update != {}:
                safe_print("internal cycle: {}  and payload {}".format(repr(update), repr(payload)))
            abort, cur_update, cur_payload = self.statemachine(payload, metadata)
            if cur_payload:
                payload = cur_payload
            if cur_update:
                QueueNode.apply_metadata_update(update, cur_update)
                QueueNode.apply_metadata_update(metadata, cur_update)
            if abort:
                break

        return update, payload

    def create_update(self, new_state, additional_data):
        ret = {}
        ret["state"] = new_state
        ret["attention_execs"] = self.stage_info_execs
        ret["attention_secs"] = time.time() - self.stage_info_start_time
        ret["state_time_initial"] = self.initial_time
        ret["state_time_havoc"] = self.havoc_time
        ret["state_time_grimoire"] = self.grimoire_time
        ret["state_time_grimoire_inference"] = self.grimoire_inference_time
        ret["state_time_redqueen"] = self.redqueen_time

        if additional_data:
            ret.update(additional_data)

        return ret

    def statemachine(self, payload, metadata):
        self.stage_info_start_time = time.time()
        self.stage_info_execs = 0
        self.attention_secs_start = metadata.get("attention_secs", 0)
        self.attention_execs_start = metadata.get("attention_execs", 0)

        self.initial_time = 0
        self.havoc_time = 0
        self.grimoire_time = 0
        self.grimoire_inference_time = 0
        self.redqueen_time = 0

        if metadata["state"]["name"] == "import":
            self.handle_import(payload, metadata)
            return True, None, None
        elif metadata["state"]["name"] == "grimoire_inference":
            grimoire_info, payload = self.handle_grimoire_inference(payload, metadata)
            return True, self.create_update({"name": "initial"}, {"grimoire": grimoire_info}), None
        elif metadata["state"]["name"] == "initial":
            new_payload = self.handle_initial(payload, metadata)
            return False, self.create_update({"name": "deterministic"}, None), new_payload
        elif metadata["state"]["name"] == "deterministic":
            self.handle_deterministic(payload, metadata)
            return False, self.create_update({"name": "havoc"}, None), None
        elif metadata["state"]["name"] == "havoc":
            self.handle_havoc(payload, metadata)
            return False, self.create_update({"name": "finished"}, None), None
        elif metadata["state"]["name"] == "finished":
            self.handle_havoc(payload, metadata)
            return False, self.create_update({"name": "finished"}, None), None
        else:
            raise "Unknown task type {}".format(metadata["state"]["name"])

    def handle_import(self, payload, metadata):
        info = {"method": "import",
                "parent": None,
                }
        self.execute(payload, info)

    def handle_initial(self, payload, metadata):
        time_initial_start = time.time()
        center_trim = False

        default_info = {"method": "trim", "parent": metadata["id"]}
        new_payload = perform_trim(payload, metadata, self.execute_with_bitmap, default_info,
                                   self.slave.execution_exited_abnormally)

        if center_trim:
            default_info = {"method": "center_trim", "parent": metadata["id"]}
            new_payload = perform_center_trim(new_payload, metadata, self.execute_with_bitmap, default_info,
                                              self.slave.execution_exited_abnormally, trimming_bytes=2)
        self.initial_time += time.time() - time_initial_start
        if new_payload == payload:
            return None
        safe_print("before trim:\t\t{}".format(repr(payload)))
        safe_print("after trim:\t\t{}".format(repr(new_payload)))
        return new_payload

    def handle_grimoire_inference(self, payload, metadata):
        grimoire_info = {}
        payload_changed = False

        default_info = {"method": "grimoire_inference", "parent": metadata["id"]}
        new_bytes = metadata["new_bytes"]

        if len(new_bytes) > 0 and len(payload) < 16384:
            start_time = time.time()

            # generalize
            generalized_printable, generalized_input = self.grimoire.generalize_input(payload, metadata,
                                                                                      default_info)

            # check if generalization failed
            if generalized_printable is None and generalized_input is None:
                return grimoire_info, None

            # store generalized input
            grimoire_info["generalized_printable"] = generalized_printable
            grimoire_info["generalized_input"] = generalized_input

            self.grimoire_inference_time = time.time() - start_time
            log_grimoire("generalization took {} seconds".format(self.grimoire_inference_time))

            # set new payload
            # payload_changed = True
            # payload = new_payload

            # validate payload
            # payload_test = perform_center_trim(payload, task["node"], self.execute,
            #                           {"method": "center_trim", "parent": task["node"]["id"]},
            #                           self.slave.execution_exited_abnormally, trimming_bytes=1)
            # if payload != payload_test:
            #     safe_print("generalized payload:\t".format(repr(payload)))
            #     safe_print("trimmed payload:\t".format(repr(payload_test)))
            #     assert False

        log_grimoire("number of unique generalized inputs: {}".format(len(self.grimoire.generalized_inputs.keys())))
        return grimoire_info, payload if payload_changed else None

    def handle_grimoire(self, payload, metadata):
        default_info = {"method": "grimoire", "parent": metadata["id"]}

        grimoire_info = None
        if "grimoire" in metadata:
            grimoire_info = metadata["grimoire"]

        self.__perform_grimoire(payload, metadata, grimoire_info, default_info)

    def __perform_grimoire(self, payload, metadata, grimoire_info, default_info):
        perf = 1 / metadata["info"]["performance"]
        if grimoire_info and "generalized_input" in grimoire_info:
            havoc_amount = havoc.havoc_range(perf * self.HAVOC_MULTIPLIER * 2.0)
            if len(self.grimoire.generalized_inputs) < havoc_amount / 4:
                havoc_amount = len(self.grimoire.generalized_inputs) * 2
            grimoire.havoc(tuple(grimoire_info["generalized_input"]), self.execute, default_info, self.grimoire,
                           havoc_amount,
                           generalized=True)
        else:
            havoc_amount = havoc.havoc_range(perf * self.HAVOC_MULTIPLIER)
            if len(self.grimoire.generalized_inputs) < havoc_amount / 4:
                havoc_amount = len(self.grimoire.generalized_inputs)
            generalized_input = tuple(["gap"] + [c for c in payload] + ["gap"])
            grimoire.havoc(generalized_input, self.execute, default_info, self.grimoire, havoc_amount,
                           generalized=False)

    def handle_deterministic(self, payload, metadata):
        payload_array = array('B', payload)
        limiter_map = self.__calc_initial_effector_map(payload_array)

        redqueen_start_time = time.time()
        self.__perform_redqueen(payload_array, metadata)
        self.redqueen_time += time.time() - redqueen_start_time

        self.__perform_deterministic(payload_array, metadata, limiter_map)

        self.handle_havoc(payload, metadata)

    def handle_havoc(self, payload, metadata):
        payload_array = array('B', payload)
        havoc_start_time = time.time()
        grimoire_time = 0

        self.__perform_dict(payload_array, metadata)
        self.num_findings_in_havoc_stage = 0

        for i in range(16):
            num_of_finds_tmp = self.num_findings_in_havoc_stage
            grimoire_start_time = time.time()
            self.handle_grimoire(payload, metadata)
            grimoire_time += time.time() - grimoire_start_time
            self.__perform_havoc(payload_array, metadata, use_splicing=(i > 0))
            if self.num_findings_in_havoc_stage == num_of_finds_tmp:
                break
        self.havoc_time += time.time() - havoc_start_time - grimoire_time
        self.grimoire_time += grimoire_time

    def execute(self, data, info=None):
        self.stage_info_execs += 1
        if info:
            info["attention_execs"] = self.attention_execs_start + self.stage_info_execs
            info["attention_secs"] = self.attention_secs_start + time.time() - self.stage_info_start_time
        is_new = self.slave.execute(data, info)
        if is_new:
            self.num_findings_in_havoc_stage += 1
        return is_new

    def execute_with_bitmap(self, data, info=None):
        self.stage_info_execs += 1

        if info:
            info["attention_execs"] = self.attention_execs_start + self.stage_info_execs
            info["attention_secs"] = self.attention_secs_start + time.time() - self.stage_info_start_time
        bitmap, new_input = self.slave.execute_with_bitmap(data, info)
        if new_input:
            self.num_findings_in_havoc_stage += 1
        return bitmap, new_input

    def execute_redqueen(self, data):
        self.stage_info_execs += 1
        return self.slave.execute_redqueen(data)

    def __perform_redqueen(self, payload_array, metadata):
        if self.config.argument_values['r']:
            default_info = {"method": "colorization", "parent": metadata["id"]}

            payload_bytes = array('B', payload_array)

            orig_hash = self.__get_bitmap_hash_robust(payload_bytes, default_info)
            extension = array("B", [207, 117, 130, 107, 183, 200, 143, 154])
            appended_hash = self.__get_bitmap_hash_robust(payload_bytes + extension, default_info)

            if orig_hash and orig_hash == appended_hash:
                safe_print("input can be extended")
                payload_bytes += extension

            colored_alternatives = self.__perform_coloring(payload_bytes, default_info)
            if colored_alternatives:
                payload_bytes = array('B', colored_alternatives[0])
            else:
                safe_print("input is not stable, skip redqueen")
                return

            t = time.time()
            rq_info = RedqueenInfoGatherer()
            rq_info.make_paths(RedqueenWorkdir(self.slave.slave_id, self.config))
            rq_info.verbose = False
            for payload in colored_alternatives:
                if self.execute_redqueen(payload):
                    rq_info.get_info(payload)

            rq_info.get_proposals()
            default_info = {"method": "redqueen", "parent": metadata["id"]}
            rq_info.run_mutate_redqueen(payload_bytes, self.execute, default_info)

            if False and self.mode_fix_checksum:
                for addr in rq_info.get_hash_candidates():
                    self.redqueen_state.add_candidate_hash_addr(addr)

            # for addr in rq_info.get_boring_cmps():
            #    self.redqueen_state.blacklist_cmp_addr(addr)
            # self.redqueen_state.update_redqueen_blacklist(RedqueenWorkdir(0))

            duration = time.time() - t

    def dilate_effector_map(self, effector_map, limiter_map):
        effector_map[0] = 1
        effector_map[-1] = 1
        for i in xrange(len(effector_map) / 8):
            base = i * 8
            effector_slice = effector_map[base:base + 8]
            limiter_slice = limiter_map[base:base + 8]
            if any(effector_slice) and any(limiter_slice):
                for j in xrange(len(effector_slice)):
                    effector_map[i + j] = 1

    def __perform_deterministic(self, payload_array, metadata, limiter_map):
        if self.config.argument_values['D']:
            # log_master("Bit Flip...")
            skip_zero = self.config.argument_values['s']
            arith_max = self.config.config_values["ARITHMETIC_MAX"]
            use_effector_map = self.config.argument_values['d']

            default_info = {"method": "deterministic", "parent": metadata["id"]}

            # TODO maybe add autodict learning
            bitflip.mutate_seq_walking_bits_array(payload_array, self.execute, default_info, skip_null=skip_zero,
                                                  effector_map=limiter_map)
            bitflip.mutate_seq_two_walking_bits_array(payload_array, self.execute, default_info, skip_null=skip_zero,
                                                      effector_map=limiter_map)
            bitflip.mutate_seq_four_walking_bits_array(payload_array, self.execute, default_info, skip_null=skip_zero,
                                                       effector_map=limiter_map)

            effector_map = None
            if use_effector_map and len(payload_array) > 128:
                effector_map = array("B", limiter_map)

                bitflip.mutate_seq_walking_byte_array(payload_array, self.execute_with_bitmap, default_info,
                                                      skip_null=skip_zero,
                                                      limiter_map=limiter_map, effector_map=effector_map)

            if use_effector_map and len(payload_array) > 128:
                self.dilate_effector_map(effector_map, limiter_map)
            else:
                # log_master("No effector map!")
                effector_map = limiter_map

                bitflip.mutate_seq_two_walking_bytes_array(payload_array, self.execute, default_info,
                                                           effector_map=effector_map)

            # log_master("Arithmetic...")
            arithmetic.mutate_seq_8_bit_arithmetic_array(payload_array, self.execute, default_info, skip_null=skip_zero,
                                                         effector_map=effector_map, set_arith_max=arith_max)
            arithmetic.mutate_seq_16_bit_arithmetic_array(payload_array, self.execute, default_info,
                                                          skip_null=skip_zero,
                                                          effector_map=effector_map, set_arith_max=arith_max)
            arithmetic.mutate_seq_32_bit_arithmetic_array(payload_array, self.execute, default_info,
                                                          skip_null=skip_zero,
                                                          effector_map=effector_map, set_arith_max=arith_max)

            # log_master("Interesting...")
            interesting_values.mutate_seq_8_bit_interesting_array(payload_array, self.execute, default_info,
                                                                  skip_null=skip_zero,
                                                                  effector_map=effector_map)
            interesting_values.mutate_seq_16_bit_interesting_array(payload_array, self.execute, default_info,
                                                                   skip_null=skip_zero,
                                                                   effector_map=effector_map, set_arith_max=arith_max)
            interesting_values.mutate_seq_32_bit_interesting_array(payload_array, self.execute, default_info,
                                                                   skip_null=skip_zero,
                                                                   effector_map=effector_map, set_arith_max=arith_max)

    def __perform_dict(self, payload_array, metadata):
        # log_master("Dict on %s" % repr(payload_array.tostring()))
        default_info = {"method": "redqueen-dict", "parent": metadata["id"]}
        rq_dict = havoc.get_redqueen_dict()
        # log_redq("using %s" % repr(rq_dict))
        counter = 0
        seen_addr_to_value = havoc.get_redqueen_seen_addr_to_value()
        if len(payload_array) < 256:
            for addr in rq_dict:
                for repl in rq_dict[addr]:
                    if addr in seen_addr_to_value and (
                            len(seen_addr_to_value[addr]) > 32 or repl in seen_addr_to_value[addr]):
                        continue
                    if not addr in seen_addr_to_value:
                        seen_addr_to_value[addr] = set()
                    seen_addr_to_value[addr].add(repl)
                    # log_master("try %s"%repr(repl))
                    for i in range(len(payload_array)):
                        counter += 1
                        mutated = havoc.apply_dict_to_data(payload_array, repl, i).tostring()
                        # log_redq("dict_bf %d %s %s"%(i,repr(repl),repr(mutated)))
                        self.execute(mutated, default_info)
        # log_redq("have performed %d iters" % counter)

    def __perform_havoc(self, payload_array, metadata, use_splicing):
        # log_master("Havoc...")
        default_info = {"method": "havoc", "parent": metadata["id"]}
        perf = 1 / metadata["info"]["performance"]
        if metadata and len(metadata["fav_bits"]) > 0:
            havoc_amount = havoc.havoc_range(perf * self.HAVOC_MULTIPLIER * 2.0)
            # radamsa_amount = havoc.havoc_range(
            #     perf * self.HAVOC_MULTIPLIER * 2.0) / self.RADAMSA_DIV
        else:
            havoc_amount = havoc.havoc_range(perf * self.HAVOC_MULTIPLIER)
            # radamsa_amount = havoc.havoc_range(perf * self.HAVOC_MULTIPLIER) / self.RADAMSA_DIV

        if not use_splicing:
            havoc.mutate_seq_havoc_array(payload_array, self.execute, default_info, havoc_amount)
        else:
            havoc.mutate_seq_splice_array(payload_array, self.execute, default_info, havoc_amount)

        # radamsa.mutate_seq_radamsa_array(payload_array, self.execute, default_info, radamsa_amount)

    def __check_colorization(self, orig_hash, payload_array, min, max, default_info):
        backup = payload_array[min:max]
        for i in xrange(min, max):
            payload_array[i] = random.randint(0, 255)
        new_hash = self.__get_bitmap_hash(payload_array, default_info)
        if new_hash is not None and new_hash == orig_hash:
            return True
        else:
            payload_array[min:max] = backup
            return False

    def __colorize_payload(self, orig_hash, payload_array, default_info):
        def checker(min_i, max_i):
            self.__check_colorization(orig_hash, payload_array, min_i, max_i, default_info)

        c = ColorizerStrategy(len(payload_array), checker)
        t = time.time()
        i = 0
        while True:
            if i >= FuzzingStateLogic.COLORIZATION_STEPS and time.time() - t > FuzzingStateLogic.COLORIZATION_TIMEOUT:  # TODO add to config
                break
            if len(c.unknown_ranges) == 0:
                break
            c.colorize_step()
            i += 1

    def __get_bitmap_hash(self, payload, default_info):
        bitmap, _ = self.execute_with_bitmap(payload.tostring(), default_info)
        if bitmap is None:
            return None
        return bitmap.hash()

    def __get_bitmap_hash_robust(self, payload_array, default_info):
        hashes = {self.__get_bitmap_hash(payload_array, default_info) for _ in xrange(3)}
        if len(hashes) == 1:
            return hashes.pop()
        # log_master("Hash Doesn't seem Stable")
        return None

    def __perform_coloring(self, payload_array, default_info):
        # log_master("Initial Redqueen Colorize...")
        orig_hash = self.__get_bitmap_hash_robust(payload_array, default_info)
        if orig_hash is None:
            return None
        # log_master("Orig Redqueen Colorize...(" + str(orig_hash) + ")")

        colored_arrays = []
        for i in xrange(FuzzingStateLogic.COLORIZATION_COUNT):
            if len(colored_arrays) >= FuzzingStateLogic.COLORIZATION_COUNT:
                assert False  # TODO remove me
            arr = array("B", payload_array)
            self.__colorize_payload(orig_hash, arr, default_info)
            new_hash = self.__get_bitmap_hash(arr, default_info)
            if new_hash is not None and new_hash == orig_hash:
                colored_arrays.append(arr)
                # log_master("found good orig_hash")
            else:
                # log_master("found bad orig_hash: " + repr(new_hash) + " retry")
                return None

        colored_arrays.append(payload_array)
        return colored_arrays
