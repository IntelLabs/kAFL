#!/bin/bash
#
# Copyright 2020 Intel Corporation
# SPDX-License-Identifier: MIT
#

# Given a workdir with per-payload trace files in traces/, grep and sort your
# way through all the traces to obtain list of unique discovered edges.

WORKDIR="$1"; shift

function usage() {
	echo -e "Usage:\n\t$1 <workdir>\n"
	exit
}

function fatal_exit() {
	echo "$1"
	exit
}

test -d "$WORKDIR" || usage "$0"
test -d "$WORKDIR/traces/" || fatal_exit "Could not find $WORKDIR/traces/"

which lz4cat || fatal_exit "Could not find lz4cat tool."
which mktemp || fatal_exit "Could not find mktemp tool."

TMPFILE=$(mktemp)
OUTFILE="$WORKDIR/traces/edges_uniq.lst"

pushd "$WORKDIR/traces/"

# can be LOTS of traces, so do sort/uniq on individual files first..
for trace in ./payload_*.lz4; do
	echo "lz4cat $trace |grep edge|sort -u >> $TMPFILE"
	lz4cat $trace|grep edge|sort -u >> $TMPFILE
done

echo -n "Sorting final output..."
sort -u $TMPFILE |sed -e 's/.*\[//' -e 's/\].*//' > $OUTFILE
rm $TMPFILE
echo -e "done!\nGot $(wc -l $OUTFILE) edges in $OUTFILE"

popd
