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

KAFL_OPTS="-p $(nproc) -grimoire -redqueen -hammer_jmp_tables -catch_reset"

function build_app() {

	if [[ -z "$ZEPHYR_TOOLCHAIN_VARIANT" ]] || [[ -z "$ZEPHYR_BASE" ]]; then
		printf "\tError: Zephyr SDK is not active, skipping Zephyr targets!\n"
		exit
	fi

	# select target app / variant
	APP=$1; shift || APP="TEST"

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
	echo -e "\tbuild <TEST|JSON|FS>  - build the test, json or fs fuzzing sample"
	echo -e "\trun [args]  - run the currently build sample with optional kAFL args"
	echo -e "\tcov <dir>   - process corpus of existing workdir and collect coverage info"
	echo
	exit
}


CMD=$1; shift || usage

case $CMD in
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
