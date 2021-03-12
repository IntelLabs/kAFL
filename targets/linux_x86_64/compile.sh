#!/bin/bash
#
# This file is part of Redqueen.
#
# Copyright 2019 Sergej Schumilo, Cornelius Aschermann
#
# SPDX-License-Identifier: MIT
#
if [[ "$OSTYPE" == "linux-gnu" ]]; then

	mkdir bin/ 2> /dev/null
	mkdir bin/loader/ 2> /dev/null
	mkdir bin/fuzzer/ 2> /dev/null
	mkdir bin/info/ 2> /dev/null

	printf "\tCompiling loader...\n"
	gcc src/loader/loader.c  -static -I ../ -o bin/loader/loader
	printf "\tCompiling stage 2 loader...\n"
    gcc -c -O0 src/loader/stage2_loader.c -I ../ -o bin/loader/stage2_loader.o
	printf "\tCompiling info executable...\n"
	gcc -static src/info/info.c -I ../ -o bin/info/info
	printf "\tCompiling vuln_driver fuzzer...\n"
	gcc src/fuzzer/kafl_vuln_test.c -I ../ -o bin/fuzzer/kafl_vuln_test
	printf "\tCompiling kafl_vuln_json test...\n"	
	gcc src/fuzzer/kafl_vuln_json.c -I ../ -o bin/fuzzer/kafl_vuln_json
    printf "\tCompiling hprintf test...\n"
	gcc src/fuzzer/hprintf_test.c -I ../ -o bin/fuzzer/hprintf_test
	printf "\tCompiling EXT4 fuzzer...\n"
	gcc src/fuzzer/fs_fuzzer.c -I ../ -o bin/fuzzer/ext4 -D EXT4
	printf "\tCompiling NTFS fuzzer...\n"
	gcc src/fuzzer/fs_fuzzer.c -I ../ -o bin/fuzzer/ntfs -D NTFS
	printf "\tCompiling VFAT fuzzer...\n"
	gcc src/fuzzer/fs_fuzzer.c -I ../ -o bin/fuzzer/vfat -D VFAT
else
	printf "\tError: Need to run Linux to compile these components! Skipping..!\n"
fi
