#!/bin/bash
#
# Helper script to fetch / build a couple sample targets
#
# Copyright 2019-2020 Intel Corporation
# SPDX-License-Identifier: MIT
#

set -e

TARGET_ROOT="$(dirname ${PWD}/${0})"
[ -n "$KAFL_ROOT" ] || KAFL_ROOT=${PWD}

PACKAGES="$TARGET_ROOT/builds"
BIN_DIR="$TARGET_ROOT/targets"
JOBS=$((2*`nproc`))

test -d "$PACKAGES" || mkdir -p "$PACKAGES" || echo "Failed creating target workdir $PACKAGES. Exit"

build_confmake()
{
	URL="$1"
	TARBALL="$(basename $URL)"
	SRC_DIR=$(echo $TARBALL|sed "s/.tar.*//")

	test -f $TARBALL || wget -O $TARBALL "$URL"
	test -d $SRC_DIR || tar -xf $TARBALL

	test -d $SRC_DIR || echo "Error: Extracting $TARBALL did not yield expected dir $SRC_DIR. Exit"
	test -d $SRC_DIR || exit

	pushd $SRC_DIR > /dev/null
	echo "Performing configure/make for $SRC_DIR. This may take a moment.."
	./configure --without-threads --disable-shared > /dev/null
	make -j $JOBS > /dev/null
	popd > /dev/null
		
	echo "Done compiling, copying target binaries..."
}

build_cmake()
{
	URL="$1"
	TARBALL="$(basename $URL)"
	SRC_DIR=$(echo $TARBALL|sed "s/.tar.*//")

	test -f $TARBALL || wget -O $TARBALL "$URL"
	test -d $SRC_DIR || tar -xf $TARBALL

	test -d $SRC_DIR || echo "Error: Extracting $TARBALL did not yield expected dir $SRC_DIR. Exit"
	test -d $SRC_DIR || exit

	pushd $SRC_DIR > /dev/null
	echo "Performing configure/make for $SRC_DIR. This may take a moment.."
	cmake . -DENABLE_SHARED=0 > /dev/null
	make -j $JOBS
	popd > /dev/null
}

fetch_lava()
{
	# fetch precompiled version of LAVA-M
	# http://moyix.blogspot.com/2016/10/the-lava-synthetic-bug-corpora.html
	URL="https://sites.google.com/site/steelix2017/home/lava/lava.zip"
	ZIPFILE="$(basename $URL)"
	SRC_DIR=$(echo $ZIPFILE|sed "s/.zip.*//")

	test -f $ZIPFILE || wget -O $ZIPFILE "$URL"
	test -d $SRC_DIR || unzip $ZIPFILE lava/*

	test -d $SRC_DIR || echo "Error: Extracting $ZIPFILE did not yield expected dir $SRC_DIR. Exit"
	test -d $SRC_DIR || exit
}

pushd "$PACKAGES" > /dev/null
TARGET="$1"
case $TARGET in
	"nasm")
		build_confmake "https://www.nasm.us/pub/nasm/releasebuilds/2.14.02/nasm-2.14.02.tar.xz"
		cp -v $SRC_DIR/$TARGET $BIN_DIR
		;;
	"bison")
		build_confmake "https://ftp.gnu.org/gnu/bison/bison-3.5.tar.xz"
		cp -v $SRC_DIR/src/$TARGET $BIN_DIR
		;;
	"binutils")
		sudo apt-get install texinfo
		build_confmake "https://ftp.gnu.org/gnu/binutils/binutils-2.34.tar.xz"
		cp -v $SRC_DIR/binutils/{cxxfilt,size,readelf,objdump,ar} $BIN_DIR
		cp -v $SRC_DIR/binutils/nm-new $BIN_DIR
		;;
	"djpeg")
		build_cmake "https://sourceforge.net/projects/libjpeg-turbo/files/2.0.4/libjpeg-turbo-2.0.4.tar.gz"
		cp -v $SRC_DIR/djpeg-static $BIN_DIR/djpeg
		;;
	"pngtest")
		build_confmake "https://download.sourceforge.net/libpng/libpng-1.6.37.tar.xz"
		cp -v $SRC_DIR/pngtest $BIN_DIR
		;;
	"xmllint")
		build_confmake "http://xmlsoft.org/sources/libxml2-2.9.9.tar.gz"
		cp -v $SRC_DIR/xmllint $BIN_DIR
		;;
	"lava")
		fetch_lava
		for bin in base64 who md5sum uniq; do
			cp -v $SRC_DIR/bins/$bin $BIN_DIR/lava_$bin
		done
		;;
	*)
		echo "Usage: $0 <target>"
		echo
		echo "Currently enabled targets: nasm, bison, binutils, djpeg, lava."
		echo
		;;
esac

popd > /dev/null
