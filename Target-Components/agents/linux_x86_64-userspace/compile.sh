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
set -e

if [[ "$OSTYPE" == "linux-gnu" ]]; then
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

else
	printf "\tError: Cannont compile linux userspace components on this plattform!\n\tPlease use Linux instead!\n"
fi
