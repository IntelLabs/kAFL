#!/bin/bash
#
# kAFL helper script to build and launch UEFI components
#
# Copyright 2019-2020 Intel Corporation
# SPDX-License-Identifier: MIT
#

set -e

unset EDK_TOOLS_PATH
unset WORKSPACE
unset CONF_PATH
unset PACKAGES_PATH

TARGET_ROOT="$(dirname ${PWD}/${0})"
[ -n "$KAFL_ROOT" ] || KAFL_ROOT=${PWD}
[ -n "$EDK2_ROOT" ] || EDK2_ROOT=$KAFL_ROOT/edk2.git

[ -d $KAFL_ROOT/kAFL-Fuzzer ] || ( echo "Please set correct KAFL_ROOT" ; false )

#BUILD=RELEASE
BUILD=DEBUG
#ARCH=IA32
ARCH=X64
TOOL=GCC5

#APP=TestDecompress
APP=TestBMP

#BUILD_OPTS="-a IA32 -a X64 -b NOOPT -t CLANGSAN40 -n 8 -DDEBUG_ON_SERIAL_PORT"
BUILD_OPTS="-a $ARCH -b $BUILD -t $TOOL -n $(nproc)"
KAFL_OPTS="-p $(nproc) -redqueen -hammer_jmp_tables -grimoire -catch_reset"

function install_edk2()
{
	# requirements on top of kAFL base install
	sudo apt-get install nasm iasl g++ g++-multilib
	
	# download + apply patch unless install folder already exists
	if [ -d $KAFL_ROOT/edk2.git ]; then
		echo "[*] Folder exists, assume it is already patched.."
		pushd $KAFL_ROOT/edk2.git
	else
		git clone https://github.com/tianocore/edk2 $KAFL_ROOT/edk2.git
		pushd $KAFL_ROOT/edk2.git
		git checkout -b edk2-stable201905
		git submodule update --init --recursive
		patch -p1 < $TARGET_ROOT/edk2_kafl.patch || exit
	fi
	make -C BaseTools -j $(nproc)
	export EDK_TOOLS_PATH=$PWD/BaseTools
	. edksetup.sh BaseTools
	popd
}

function build_app()
{
	[ -d $EDK2_ROOT/BaseTools ] || ( echo "Please set correct EDK2_ROOT"; exit )
	pushd $EDK2_ROOT
	export PACKAGES_PATH=$TARGET_ROOT
	export EDK_TOOLS_PATH=$PWD/BaseTools
	. edksetup.sh BaseTools

	which build || exit

	build $BUILD_OPTS -p ${APP}Pkg/$APP.dsc

	echo "Build done, copy target files.."
	cp -v Build/${APP}Pkg/${BUILD}_${TOOL}/$ARCH/$APP.efi $TARGET_ROOT/fake_hda/harness.efi
	popd
}

function build_ovmf()
{
	[ -d $EDK2_ROOT/BaseTools ] || ( echo "Please set correct EDK2_ROOT"; exit )
	pushd $EDK2_ROOT
	make -C BaseTools
	export EDK_TOOLS_PATH=$PWD/BaseTools
	. edksetup.sh BaseTools

	which build || exit

	build $BUILD_OPTS -p OvmfPkg/OvmfPkg${ARCH}.dsc

	echo "Build done, copy target files.."
	[ $ARCH == "IA32" ] && ARCH="Ia32"
	cp -v Build/Ovmf${ARCH}/${BUILD}_${TOOL}/FV/OVMF.fd $TARGET_ROOT/bios.bin
	popd
}

function run()
{
	pushd $KAFL_ROOT
	# Note: -ip0 depends on your UEFI build and provided machine memory!
	#python3 kAFL-Fuzzer/kafl_fuzz.py -ip0 0xE000000-0xEF00000 --purge \
	python3 kAFL-Fuzzer/kafl_fuzz.py -ip0 0x2000000-0x2F00000 --purge \
		-bios $TARGET_ROOT/bios.bin \
		-extra " -hda fat:rw:$TARGET_ROOT/fake_hda -net none -no-reboot" \
		-mem 64 \
		-seed_dir $TARGET_ROOT/seeds/ \
		-work_dir /dev/shm/kafl_uefi \
		$KAFL_OPTS $*
	popd
}

function noise()
{
	pushd $KAFL_ROOT
	TEMPDIR=$(mktemp -d -p /dev/shm)
	WORKDIR=$1; shift
	echo
	echo "Using temp workdir >>$TEMPDIR<<.."
	echo
	sleep 1

	# Note: -ip0 and other VM settings should match those used during fuzzing
	python3 kAFL-Fuzzer/kafl_debug.py -action noise -ip0 0x2000000-0x2F00000 --purge \
		-bios $TARGET_ROOT/bios.bin \
		-extra " -hda fat:rw:$TARGET_ROOT/fake_hda -net none -no-reboot" \
		-mem 64 \
		-work_dir $TEMPDIR \
		-input $WORKDIR $*
	popd
}

function cov()
{
	pushd $KAFL_ROOT
	TEMPDIR=$(mktemp -d -p /dev/shm)
	WORKDIR=$1
	echo
	echo "Using temp workdir >>$TEMPDIR<<.."
	echo
	sleep 1

	# Note: -ip0 and other VM settings should match those used during fuzzing
	python3 kAFL-Fuzzer/kafl_cov.py -v -ip0 0x2000000-0x2F00000 --purge \
		-bios $TARGET_ROOT/bios.bin \
		-extra " -hda fat:rw:$TARGET_ROOT/fake_hda -net none -no-reboot" \
		-mem 64 \
		-work_dir $TEMPDIR \
		-input $WORKDIR
	popd
}

function usage() {
	echo
	echo "Build and run the UEFI OVMF sample."
	echo
	echo "This script assumes KAFL at $KAFL_ROOT and EDK2 cloned to $EDK2_ROOT."
	echo "Build settings in Conf/target.txt will be overridden with '$BUILD_OPTS'."
	echo
	echo "Usage: $0 <edk2|ovmf|app|run>"
	echo
	echo Parameters:
	echo "     edk2 - download edk2 branch + build deps"
	echo "     ovmf - build baseline OVMF firmware"
	echo "     app  - build kAFL sample agent"
	echo "     run  - run sample agent in kAFL"
	echo "     cov <dir> - process <dir> in trace mode to collect coverage info"
	echo "     noise <file> - process <file> in trace mode to collect coverage info"
	exit
}


CMD=$1; shift || usage

case $CMD in
	"run")
		run $*
		;;
	"noise")
		test -f "$1" || usage
		noise $*
		;;
	"cov")
		test -d "$1" || usage
		cov $1
		;;
	"edk2")
		install_edk2
		;;
	"ovmf")
		build_ovmf
		;;
	"app")
		build_app
		;;
	*)
		usage
		;;
esac
