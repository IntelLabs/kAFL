#!/bin/bash
#
# Helper script to package and launch Linux userspace binaries.
# Targets are packed in a Linux initrd and launched via Qemu -kernel -initrd
#
# This script assumes a <target> binary and corresponding .env file in bins/.
# Basic shared libraries are automatically copied from the host system into the initrd.
#
# Copyright 2019-2020 Intel Corporation
# SPDX-License-Identifier: MIT
#

set -e

TARGET_ROOT="$(dirname ${PWD}/${0})"
[ -n "$KAFL_ROOT" ] || KAFL_ROOT=${PWD}

# Grab a Linux kernel to boot... current running image will do..
LINUX_KERNEL="/boot/vmlinuz-5.6.0-1-amd64"
LINUX_KERNEL="/boot/vmlinuz-$(uname -r)"
KAFL_FUZZ_OPTIONS="-redqueen -grimoire -p $(nproc) -forkserver -radamsa"

target_pack()
{
	echo "[*] Packing target >>$TARGET<<"
	
	rm -rf "$PACKDIR"
	mkdir -p "$PACKDIR"

	bash ./targets/linux_x86_64-userspace/compile.sh

	source "$BIN_DIR/$TARGET.env"

	readelf -h $BIN_DIR/$TARGET |grep -q ELF64 && TARGET_ARCH=m64
	readelf -h $BIN_DIR/$TARGET |grep -q ELF32 && TARGET_ARCH=m32

	# TODO: shell script would be much easier than python?
	python3 kAFL-Fuzzer/kafl_user_prepare.py \
		--recompile \
		"$TARGET_ARGS" \
		"$TARGET_FILE" \
		"$BIN_DIR/$TARGET" \
		"$PACKDIR/" $TARGET_ARCH

	bash targets/linux_x86_64-userspace/initrd/pack.sh \
		"$PACKDIR/${TARGET}_info_initrd.gz" \
		"$PACKDIR/${TARGET}_info"

	bash targets/linux_x86_64-userspace/initrd/pack.sh \
		"$PACKDIR/${TARGET}_fuzz_initrd.gz" \
		"$PACKDIR/${TARGET}_fuzz"
}

target_run()
{
	echo "[*] Get info on target $TARGET"

	rm -rf "$WORKDIR"
	mkdir -p "$WORKDIR"
		
	python3 kAFL-Fuzzer/kafl_info.py \
		-kernel "$LINUX_KERNEL" \
		-initrd "$PACKDIR/${TARGET}_info_initrd.gz" \
		-mem 512 \
		-work_dir "$WORKDIR" \
		-v |tee $WORKDIR/info.log

	IP_RANGE="$(cat $WORKDIR/info.log|grep target_executable|grep -- r-xp |head -1|cut -d\  -f 1|sed -e 's/^0/0x/' -e 's/\-0/-0x/')"

	echo "[*] Start fuzzing with range $IP_RANGE, args $KAFL_FUZZ_OPTIONS"

	python3 kAFL-Fuzzer/kafl_fuzz.py \
		-kernel "$LINUX_KERNEL" \
		-initrd "$PACKDIR/${TARGET}_fuzz_initrd.gz" \
		-mem 512 \
		-work_dir "$WORKDIR" \
		-seed_dir "$TARGET_ROOT/seeds/" \
		--purge \
		-ip0 $IP_RANGE $KAFL_FUZZ_OPTIONS $*
}

target_cov()
{
	echo "[*] Get trace & coverage data on target $TARGET"
	TMP_WORKDIR="/dev/shm/kafl_tmp_$TARGET/"

	python3 kAFL-Fuzzer/kafl_info.py \
		-kernel "$LINUX_KERNEL" \
		-initrd "$PACKDIR/${TARGET}_info_initrd.gz" \
		-mem 512 \
		-work_dir "$TMP_WORKDIR" \
		-v |tee $TMP_WORKDIR/info.log

	IP_RANGE="$(cat $TMP_WORKDIR/info.log|grep target_executable|grep xp\ |cut -d\  -f 1|sed -e 's/^0/0x/' -e 's/\-0/-0x/')"

	python3 kAFL-Fuzzer/kafl_cov.py \
		-kernel "$LINUX_KERNEL" \
		-initrd "$PACKDIR/${TARGET}_fuzz_initrd.gz" \
		-mem 512 \
		-work_dir "$TMP_WORKDIR" \
		-input $1
		--purge \
		-ip0 $IP_RANGE $*
}

CMD="$1"
TARGET="$2"

BIN_DIR="$TARGET_ROOT/targets/"
PACKDIR="$TARGET_ROOT/packed/$TARGET/"
WORKDIR="/dev/shm/kafl_$TARGET/"

cd "$KAFL_ROOT"

case $CMD in
	"pack")
		target_pack
		;;
	"run")
		shift 2
		target_run $*
		;;
	"cov")
		shift 2
		test -d "$1" || exit
		target_cov $1
		;;
	*)
		echo "$0 <pack|run|cov> <target>"
		;;
esac
