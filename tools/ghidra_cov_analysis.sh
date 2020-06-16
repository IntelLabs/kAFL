#!/bin/bash
#
# Helper script to launch Ghidra coverage analysis with given kAFL traces and target ELF.
#
# Copyright 2020 Intel Corporation
# SPDX-License-Identifier: MIT

KAFL_ROOT=~/kafl
GHIDRA_ROOT=~/ghidra_9.1_PUBLIC
WORKDIR="$1" # kAFL work dir with traces/ folder
TARGET="$2"  # original target input (tested with basic ELF file loaded as -kernel)

BIN=$GHIDRA_ROOT/support/analyzeHeadless
PROJDIR=$GHIDRA_ROOT/work
PROJ=cov_analysis

test -f "$BIN" || exit
test -d "$PROJDIR" || exit
test -f "$TARGET" || exit
test -f "$KAFL_ROOT/tools/ghidra_cov_analysis.py" || exit

# Check if traces have been generated and optionally create unique edges file
test -f "$WORKDIR/traces/coverage.csv" || exit
test -f "$WORKDIR/traces/edges_uniq.lst" || $KAFL_ROOT/tools/unique_edges.sh $WORKDIR

# TODO: how can we hand the file argument directly to ghidra script?
ln -sf "$WORKDIR/traces/edges_uniq.lst" /tmp/edges_uniq.lst

# create project and import binary - slow but only required once per binary
$BIN $PROJDIR $PROJ -import $TARGET -overwrite
# analyse coverage
$BIN $PROJDIR $PROJ -process $(basename $TARGET) -scriptPath "$KAFL_ROOT"/tools/ -postscript ghidra_cov_analysis.py
