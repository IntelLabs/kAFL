# This file is part of Redqueen.
#
# Copyright 2019 Sergej Schumilo, Cornelius Aschermann
#
# SPDX-License-Identifier: MIT
#

mkdir bin/ 2> /dev/null

gcc src/vuln.c -m64 -D STDIN_INPUT -g -o bin/vuln_stdin_64 
gcc src/vuln.c -m32 -D STDIN_INPUT -g -o bin/vuln_stdin_32  

gcc src/vuln.c -m32 -D STDIN_INPUT -g -fsanitize=address -o bin/vuln_stdin_32_asan
gcc src/vuln.c -m64 -D STDIN_INPUT -g -fsanitize=address -o bin/vuln_stdin_64_asan

gcc src/vuln.c -m64 -D FILE_INPUT -g -o bin/vuln_file_64  
gcc src/vuln.c -m32 -D FILE_INPUT -g -o bin/vuln_file_32 

gcc src/loop.c -m64 -D STDIN_INPUT -g -o bin/loop_stdin_64 
gcc src/loop.c -m32 -D STDIN_INPUT -g -o bin/loop_stdin_32  
gcc src/loop.c -m64 -D FILE_INPUT -g -o bin/loop_file_64  
gcc src/loop.c -m32 -D FILE_INPUT -g -o bin/loop_file_32 
