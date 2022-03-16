#!/bin/bash

# Copyright (C) Intel Corporation, 2022
# SPDX-License-Identifier: MIT
#
# Generate a .env file to be sourced by pipenv
# Add your own / additional project locations here.

set -e

if ! which west > /dev/null; then
	echo "Could not find west. Run this script from within the west workspace and python venv."
	exit -1
fi

if ! west list manifest > /dev/null; then
	echo "Failed to locate West manifest - not initialized?"
	exit -1
fi

# silence missing Zephyr install?
if ! west list zephyr > /dev/null 2>&1; then
   if ! west config zephyr.base > /dev/null; then
	   west config zephyr.base not-using-zephyr
   fi
fi

WORKSPACE=$(west topdir); echo WORKSPACE=$WORKSPACE
KAFL_ROOT=$(west list -f {abspath} kafl); echo KAFL_ROOT=$KAFL_ROOT
QEMU_ROOT=$(west list -f {abspath} qemu); echo QEMU_ROOT=$QEMU_ROOT
LIBXDC_ROOT=$(west list -f {abspath} libxdc); echo LIBXDC_ROOT=$LIBXDC_ROOT
CAPSTONE_ROOT=$(west list -f {abspath} capstone); echo CAPSTONE_ROOT=$CAPSTONE_ROOT
RADAMSA_ROOT=$(west list -f {abspath} radamsa); echo RADAMSA_ROOT=$RADAMSA_ROOT
HOST_KERNEL=$(west list -f {abspath} host_kernel); echo HOST_KERNEL=$HOST_KERNEL

# default kAFL workdir + config
echo KAFL_CONFIG_FILE=$KAFL_ROOT/kafl.yaml
echo KAFL_WORKDIR=/dev/shm/${USER}_tdfl
