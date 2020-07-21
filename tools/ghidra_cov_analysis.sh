#!/bin/bash
#
# Helper script to launch Ghidra coverage analysis with given kAFL traces and target ELF.
#
# Copyright 2020 Intel Corporation
# SPDX-License-Identifier: MIT

KAFL_ROOT=~/kafl
GHIDRA_ROOT=~/ghidra_9.1.2_PUBLIC
WORKDIR="$1" # kAFL work dir with traces/ folder
TARGET="$2"  # original target input (tested with basic ELF file loaded as -kernel)
SCRIPT="$KAFL_ROOT/tools/ghidra_cov_analysis.py"

BIN=$GHIDRA_ROOT/support/analyzeHeadless
PROJDIR=$GHIDRA_ROOT/work
PROJ=cov_analysis


function fail {
	echo
	echo -e "$1"
	echo
	exit
}

test $# -eq 2 || fail "Missing arguments.\n\nUsage:\n\t$0 <kafl_workdir> <target_binary>"

test -f "$BIN"     || fail "Missing ghidra executable $BIN"
test -d "$PROJDIR" || fail "Missing ghidra workdir $PROJDIR"
test -f "$TARGET"  || fail "Could not find target binary at $TARGET"
test -f "$SCRIPT"  || fail "Could not find coverage anaylsis script at $SCRIPT"

# Check if traces have been generated and optionally create unique edges file
test -d "$WORKDIR/traces/" || fail "Could not find traces/ folder in workdir."
test -f "$WORKDIR/traces/edges_uniq.lst" || $KAFL_ROOT/tools/unique_edges.sh $WORKDIR

# TODO: how can we hand the file argument directly to ghidra script?
ln -sf "$WORKDIR/traces/edges_uniq.lst" /tmp/edges_uniq.lst

# create project and import binary - slow but only required once per binary
$BIN $PROJDIR $PROJ -import $TARGET -overwrite
# analyse coverage
$BIN $PROJDIR $PROJ -process $(basename $TARGET) -scriptPath "$(dirname $SCRIPT)" -postscript "$(basename $SCRIPT)"
