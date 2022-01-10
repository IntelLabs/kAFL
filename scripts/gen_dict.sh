#!/bin/bash
#
# Copyright 2020 Intel Corporation
# SPDX-License-Identifier: MIT
#

# Helper script to generate a kAFL dictionary from `strings`
#
# Usage: dict.sh <path/to/target>
# Output: kAFL dictionary file written to $CWD/dict/dict_$TARGET.txt

fatal_usage() {
	echo
	echo "$1"
	echo "Usage: $0 <path/to/target>"
	exit
}

TARGET="$1"

test -f "$TARGET" || fatal_usage "Error: Missing target executable."
test -d ./dict/ || fatal_usage "Error: $PWD/dict/ is missing or not a directory."

strings -n3 -d "$TARGET" | grep -v "\%s" | sort | uniq > "dict/dict_$(basename "$TARGET").txt"
