#!/bin/sh
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

cp  ../agents/linux_x86_64/bin/loader/loader rootTemplate/loader
mkdir rootTemplate/lib/
mkdir rootTemplate/lib64/
mkdir rootTemplate/lib/i386-linux-gnu/
mkdir rootTemplate/lib/x86_64-linux-gnu/

cp /lib/ld-linux.so.2 rootTemplate/lib/ld-linux.so.2
cp /lib64/ld-linux-x86-64.so.2 rootTemplate/lib64/ld-linux-x86-64.so.2
cp /lib/x86_64-linux-gnu/libdl.so.2 rootTemplate/lib/x86_64-linux-gnu/libdl.so.2
cp /lib/i386-linux-gnu/libdl.so.2 rootTemplate/lib/i386-linux-gnu/libdl.so.2

cp -r "rootTemplate" "init"
sed '/START/c\./loader' init/init_template > init/init
chmod 755 "init/init"
cd "init"

find . -print0 | cpio --null -ov --format=newc  2> /dev/null | gzip -9 > "../init.cpio.gz" 2> /dev/null
cd ../
rm -r ./init/


cp -r "rootTemplate" "init"
sed '/START/c\sh' init/init_template > init/init
chmod 755 "init/init"
cd "init"

find . -print0 | cpio --null -ov --format=newc  2> /dev/null | gzip -9 > "../init_debug_shell.cpio.gz"  2> /dev/null
cd ../
rm -r ./init/

rm -r rootTemplate/lib/
rm -r rootTemplate/lib64/
rm rootTemplate/loader
