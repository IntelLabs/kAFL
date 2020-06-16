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

printf "\nlinux_x86_64 userspace components...\n"
echo "------------------------------------"
cd linux_x86_64
bash compile.sh
cd ../

printf "\nmacOS_x86_64 userspace components...\n"
echo "------------------------------------"
cd macOS_x86_64
bash compile.sh
cd ../

printf "\nwindows_x86_64 userspace components...\n"
echo "------------------------------------"
cd windows_x86_64
bash compile.sh
cd ../

printf "\nlinux_x86_64 userspace components for userspace fuzzing...\n"
echo "------------------------------------"
cd linux_x86_64-userspace
bash compile.sh
cd ../

printf "\ndone...\n"
