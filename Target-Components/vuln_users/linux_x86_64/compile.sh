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
