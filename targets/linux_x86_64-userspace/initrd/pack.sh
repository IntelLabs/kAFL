#!/bin/bash
#
# This file is part of Redqueen.
#
# Copyright 2019 Sergej Schumilo, Cornelius Aschermann
# Copyright 2020 Intel Corporation
#
# SPDX-License-Identifier: MIT
#

set -e

SCRIPT_ROOT="$(dirname ${PWD}/${0})"
DEST=${SCRIPT_ROOT}/initrd
TEMP=${SCRIPT_ROOT}/template


error_exit() {

	echo "Fatal error: $1"
	echo
	echo "Usage:"
	echo "   $0 <output_initrd> <fuzz_agent> [other_agent]..."
	exit
}

test -d "$TEMP" || error_exit "Could not find initrd template in >>$TEMP<<"
test -x "$DEST" && error_exit "Target directory >>$DEST<< already exists."

# check arguments for optional output file
OUTPUT_FILE="$1"; shift || error_exit "Missing argument <output_initrd>"
DEFAULT_AGENT="$1"; shift || error_exit "Missing argument <fuzz_agent>"
BUSYBOX=$(which busybox) || error_exit "Could not find busybox binary."

touch -- "$OUTPUT_FILE" || error_exit "Failed accessing desired output file >>$OUTPUT_FILE<<."

echo "[*] Creating target initrd at $DEST"
cp -a "$TEMP" "$DEST"
for lib in \
	lib/ld-linux.so.2 \
	lib64/ld-linux-x86-64.so.2 \
	lib/x86_64-linux-gnu/libc.so.6 \
	lib/x86_64-linux-gnu/libdl.so.2 \
	lib/i386-linux-gnu/libc.so.6 \
	lib/i386-linux-gnu/libdl.so.2;
do
	cp -v "/$lib" "$DEST/$lib"
done

echo "[*] Adding desired agent(s)..."
for agent in "$DEFAULT_AGENT" "$@"; do
	cp -v "$agent" "$DEST"/ || error_exit "Failed adding agent >>$agent<< to initrd."
done

TMPFILE=$(tempfile)

pushd "$DEST" > /dev/null
	chmod 755 init
	chmod 755 $(basename $DEFAULT_AGENT)
	ln -s $(basename $DEFAULT_AGENT) default_agent
	cp $BUSYBOX bin/ && ./bin/busybox --install bin/
	ln bin/busybox linuxrc
	find . -print0 | cpio --null -ov --format=newc  2> /dev/null | gzip -4 > "$TMPFILE" 2> /dev/null
popd > /dev/null

mv $TMPFILE $OUTPUT_FILE
rm -f $TMPFILE

[ -d "$DEST" ] && rm -rf "$DEST"

echo "[*] Successfully created initrd at $OUTPUT_FILE"
echo

