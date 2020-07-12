#!/bin/bash
#
# kAFL helper script to build and launch Zephyr components
#
# Copyright 2019-2020 Intel Corporation
# SPDX-License-Identifier: MIT
#
set -e

TARGET_ROOT="$(dirname ${PWD}/${0})"
[ -n "$KAFL_ROOT" ] || KAFL_ROOT=${PWD}

SDK_URL="https://github.com/zephyrproject-rtos/sdk-ng/releases/download/v0.11.3/zephyr-sdk-0.11.3-setup.run"

KAFL_OPTS="-p $(nproc) -grimoire -redqueen -hammer_jmp_tables -catch_reset"

function fetch_zephyr() {
	echo -e "\nInstalling Zephyr to $KAFL_ROOT/zephyrproject.\n\n\tHit Enter to install or ctrl-c to abort."
	read
	echo "[-] Fetching dependencies.."
	# https://docs.zephyrproject.org/latest/getting_started/installation_linux.html
	sudo apt-get update
	sudo apt-get upgrade
	sudo apt-get install --no-install-recommends \
		git cmake ninja-build gperf ccache dfu-util \
		device-tree-compiler wget python3-pip python3-setuptools \
		python3-wheel python3-yaml xz-utils file make gcc gcc-multilib

	# missing deps on Ubuntu?
	sudo apt-get install python3-pyelftools

	# use west to fetch Zephyr
	pip3 install --user west
	which west || ( echo "Error: ~/.local/bin not in \$PATH?"; exit )

	echo "[-] Fetching Zephyr components.."
	pushd $KAFL_ROOT
	west init zephyrproject
	cd zephyrproject
	west update
	pip3 install --user -r zephyr/scripts/requirements.txt
	popd
}

function fetch_sdk() {

	# Download Zephyr SDK. Not pretty.
	pushd $KAFL_ROOT
	INSTALLER=$(basename $SDK_URL)

	echo -e "\nAttempting to fetch and execute Zephyr SDK installer from\n$SDK_URL\n\n\tHit Enter to continue or ctrl-c to abort."
	read
	wget -c -O $INSTALLER $SDK_URL
	bash $INSTALLER
}

function check_sdk() {

	# fetch Zephyr and SDK if not available
	test -d "$KAFL_ROOT/zephyrproject" || (echo "Could not find Zephyr."; fetch_zephyr)
	test -f "$HOME/.zephyrrc" || (echo "Could not find a Zephyr SDK."; fetch_sdk)

	# check again and this time bail out on error
	test -d "$KAFL_ROOT/zephyrproject" || (echo "Could not find Zephyr install. Exit."; exit)
	test -f "$HOME/.zephyrrc" || (echo "Could not find Zephyr SDK. Exit."; exit)
	source "$KAFL_ROOT/zephyrproject/zephyr/zephyr-env.sh"

	echo "Using Zephyr build settings:"
	echo " ZEPHYR_BASE=$ZEPHYR_BASE"
	echo " ZEPHYR_SDK_INSTALL_DIR=$ZEPHYR_SDK_INSTALL_DIR"
	echo " ZEPHYR_TOOLCHAIN_VARIANT=$ZEPHYR_TOOLCHAIN_VARIANT"
}

function build_app() {

	check_sdk

	if [[ -z "$ZEPHYR_TOOLCHAIN_VARIANT" ]] || [[ -z "$ZEPHYR_BASE" ]]; then
		printf "\tError: Zephyr SDK is not active, skipping Zephyr targets!\n"
		exit
	fi

	# select target app / variant
	APP=$1; shift

	pushd $TARGET_ROOT
	test -d build && rm -rf build
   	mkdir build || exit
	cd build
	cmake -GNinja -DBOARD=qemu_x86 -DKAFL_${APP}=y ..
	ninja
	popd
}

function run() {
	pushd $KAFL_ROOT

	BIN=${TARGET_ROOT}/build/zephyr/zephyr.elf
	MAP=${TARGET_ROOT}/build/zephyr/zephyr.map
	test -f $BIN -a -f $MAP || exit

	range=$(grep -A 1 ^text "$MAP" |xargs |cut -d\  -f 2,3)
	ip_start=$(echo $range|sed 's/ .*//')
	ip_end=$(echo -e "obase=16\nibase=16\n$(echo $range|sed s/x//g|sed 's/\ /+/'|tr a-z A-Z)"|bc)

	echo "IP filter range: $ip_start-0x$ip_end"

	python3 kAFL-Fuzzer/kafl_fuzz.py \
		-ip0 ${ip_start}-0x${ip_end} \
		-kernel ${BIN} \
		-mem 32 \
		-work_dir /dev/shm/kafl_zephyr \
		-seed_dir $TARGET_ROOT/seeds/ \
		--purge $KAFL_OPTS $*
}

function cov()
{
	pushd $KAFL_ROOT
	TEMPDIR=$(mktemp -d -p /dev/shm)
	WORKDIR=$1

	BIN=${TARGET_ROOT}/build/zephyr/zephyr.elf
	MAP=${TARGET_ROOT}/build/zephyr/zephyr.map
	test -f $BIN -a -f $MAP || exit

	range=$(grep -A 1 ^text "$MAP" |xargs |cut -d\  -f 2,3)
	ip_start=$(echo $range|sed 's/ .*//')
	ip_end=$(echo -e "obase=16\nibase=16\n$(echo $range|sed s/x//g|sed 's/\ /+/'|tr a-z A-Z)"|bc)

	echo
	echo "Using temp workdir >>$TEMPDIR<<.."
	echo "IP filter range: $ip_start-0x$ip_end"
	echo
	sleep 1


	# Note: -ip0 and other VM settings should match those used during fuzzing
	python3 kAFL-Fuzzer/kafl_cov.py \
		-v -ip0 ${ip_start}-0x${ip_end} \
		-kernel ${BIN} \
		-mem 32 \
		-work_dir $TEMPDIR \
		-input $WORKDIR
	popd
}

function usage() {
	echo
	echo "Build and run the Zephyr RTOS samples."
	echo
	echo "Usage: $0 <cmd> <args>"
	echo
	echo Available commands:
	echo -e "\tzephyr      - check Zephyr install, fetch and install any dependencies"
	echo -e "\tbuild <TEST|JSON|FS>  - build the test, json or fs fuzzing sample"
	echo -e "\trun [args]  - run the currently build sample with optional kAFL args"
	echo -e "\tcov <dir>   - process corpus of existing workdir and collect coverage info"
	echo
	exit
}


CMD=$1; shift || usage

case $CMD in
	"zephyr")
		check_sdk
		;;
	"run")
		run $*
		;;
	"cov")
		test -d "$1" || usage
		cov $1
		;;
	"build")
		test -n "$1" || usage
		build_app $1
		;;
	*)
		usage
		;;
esac
