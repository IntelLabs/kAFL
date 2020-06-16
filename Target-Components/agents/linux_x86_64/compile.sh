#!/bin/bash
# 
# This file is part of Redqueen.
#
# Copyright 
# Sergej Schumilo, 2019 <sergej@schumilo.de> 
# Cornelius Aschermann, 2019 <cornelius.aschermann@rub.de> 

# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
# documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit
# persons to whom the Software is furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
# Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
# WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
# COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
# OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
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
	printf "\tCompiling BTRFS fuzzer...\n"
	gcc src/fuzzer/fs_fuzzer.c -I ../ -o bin/fuzzer/btrfs -D BTRFS
	printf "\tCompiling XFS fuzzer...\n"
	gcc src/fuzzer/fs_fuzzer.c -I ../ -o bin/fuzzer/xfs -D XFS
	printf "\tCompiling HFS fuzzer...\n"
	gcc src/fuzzer/fs_fuzzer.c -I ../ -o bin/fuzzer/hfs -D HFS
    printf "\tCompiling HFSPLUS fuzzer...\n"
    gcc src/fuzzer/fs_fuzzer.c -I ../ -o bin/fuzzer/hfsplus -D HFSPLUS
	printf "\tCompiling ISOFS fuzzer...\n"
	gcc src/fuzzer/fs_fuzzer.c -I ../ -o bin/fuzzer/isofs -D ISOFS
	printf "\tCompiling QNX fuzzer...\n"
	gcc src/fuzzer/fs_fuzzer.c -I ../ -o bin/fuzzer/qnx -D QNX
	printf "\tCompiling FAT fuzzer...\n"
	gcc src/fuzzer/fs_fuzzer.c -I ../ -o bin/fuzzer/fat -D FAT
	printf "\tCompiling JFS fuzzer...\n"
	gcc src/fuzzer/fs_fuzzer.c -I ../ -o bin/fuzzer/jfs -D JFS
	printf "\tCompiling GFS2 fuzzer...\n"
	gcc src/fuzzer/fs_fuzzer.c -I ../ -o bin/fuzzer/gfs2 -D GFS2
	printf "\tCompiling GFS2META fuzzer...\n"
	gcc src/fuzzer/fs_fuzzer.c -I ../ -o bin/fuzzer/gfs2meta -D GFS2META
	printf "\tCompiling REISERFS fuzzer...\n"
	gcc src/fuzzer/fs_fuzzer.c -I ../ -o bin/fuzzer/reiserfs -D REISERFS
else
	printf "\tError: Cannont compile linux userspace components on this plattform!\n\tPlease use Linux instead!\n"
fi
