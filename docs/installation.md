Prerequisites: bare-metal Linux, Intel CPU with Intel PT. kAFL won't work on any kind of virtualized environment.

Tutorial was tested on Ubuntu 20.04.

1. `./install.sh check`
2. `./install.sh deps`
3. `./install.sh perms`
4. `./install.sh qemu` - may take a long time
5. Update QEMU installation path in `kafl.ini` file by following instructions printed on previous step
6. `./install.sh linux` - may take a looong time
7. Follow instructions printed on previous step to install compiled kernel. Note: either turn off Secure Boot or [sign the kernel](https://github.com/jakeday/linux-surface/blob/master/SIGNING.md) first
8. Reboot
9. `uname -r` - you should see something like `5.8.12-kAFL+`, `kAFL` being the key word here
10. `dmesg | grep VMX-PT` - you should see something like `[    2.674254] [VMX-PT] Info:   CPU is supported!`
