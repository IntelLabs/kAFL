# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.13.1)

include($ENV{ZEPHYR_BASE}/cmake/app/boilerplate.cmake NO_POLICY_SCOPE)

project(kafl_agent)
target_sources(app PRIVATE src/main.c)
set_property(TARGET app PROPERTY C_STANDARD 99)

# Select a fuzzing target at a time, e.g. ``cmake ../ -D KAFL_TEST=y''
target_sources_ifdef(KAFL_TEST  app PRIVATE src/target_test.c)
target_sources_ifdef(KAFL_FS    app PRIVATE src/target_fs.c)
target_sources_ifdef(KAFL_JSON  app PRIVATE src/target_json.c)

