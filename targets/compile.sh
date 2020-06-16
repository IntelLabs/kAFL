#
# This file is part of Redqueen.
#
# Copyright 2019 Sergej Schumilo, Cornelius Aschermann
#
# SPDX-License-Identifier: MIT
#

# Build dependencies for Linux kernel/user targets
sudo dpkg --add-architecture i386
suod apt-get update
sudo apt-get install -y gcc-multilib g++-multilib libc6-dev:i386
sudo apt-get install -y busybox-static

echo "Build samples for Linux kernel targets..."
echo "-----------------------------------------"
cd linux_x86_64
bash compile.sh
cd ../

echo "Build samples for Linux userspace targets..."
echo "--------------------------------------------"
cd linux_x86_64-userspace
bash compile.sh
cd ../

echo "Build samples MacOS kernel targets..."
echo "-------------------------------------"
cd macOS_x86_64
bash compile.sh
cd ../

echo "Build samples for Windows kernel targets..."
echo "-------------------------------------------"
cd windows_x86_64
bash compile.sh
cd ../

echo -e "\n[!] done"
