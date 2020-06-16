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

if [[ "$OSTYPE" != "linux-gnu" ]]; then
	printf "\tError: Cannont compile linux userspace components on this plattform!\n\tPlease use Linux instead!\n"
fi

pushd $SCRIPT_ROOT

printf "\tPrecompiling executables...\n"
mkdir -p bin/
mkdir -p bin/fuzzer/
mkdir -p bin/loader/
mkdir -p bin/info/

gcc -c -static -shared -O0 -m32 -Werror -fPIC src/ld_preload_info.c -o bin/ld_preload_info_32.o -ldl
gcc -c -static -shared -O0 -m64 -Werror -fPIC src/ld_preload_info.c -o bin/ld_preload_info_64.o -ldl

gcc -c -static -shared -O0 -m32 -Werror -fPIC src/ld_preload_fuzz.c -o bin/ld_preload_fuzz_32.o -ldl
gcc -c -static -shared -O0 -m64 -Werror -fPIC src/ld_preload_fuzz.c -o bin/ld_preload_fuzz_64.o -ldl

gcc -c -static -shared -O0 -m32 -Werror -fPIC -DASAN_BUILD src/ld_preload_fuzz.c -o bin/ld_preload_fuzz_32_asan.o -ldl
gcc -c -static -shared -O0 -m64 -Werror -fPIC -DASAN_BUILD src/ld_preload_fuzz.c -o bin/ld_preload_fuzz_64_asan.o -ldl

gcc -c -static -O0 -m32 -Werror src/userspace_loader.c -o bin/userspace_loader_32.o
gcc -c -static -O0 -m64 -Werror src/userspace_loader.c -o bin/userspace_loader_64.o

popd
