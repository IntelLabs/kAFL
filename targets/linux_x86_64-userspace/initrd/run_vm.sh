#!/bin/bash
#
# This file is part of Redqueen.
#
# Copyright 2019 Sergej Schumilo, Cornelius Aschermann
# SPDX-License-Identifier: MIT
#

# You can test the initramfs in Qemu like as shown below.
# To run with the modified kAFL/Qemu, disable reload+snapshots.
./qemu-4.0.0/x86_64-softmmu/qemu-system-x86_64 \
	-kernel /boot/vmlinuz-5.4.34-kAFL+ \
	-initrd targets/linux_x86_64-initramfs/init_debug_shell.cpio.gz \
	-serial mon:stdio -enable-kvm -m 500 -append "root=/dev/sda console=ttyS0" \
	-nographic -device kafl,reload_mode=False,disable_snapshot=True
