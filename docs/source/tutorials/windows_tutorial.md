# Getting Started with Windows Fuzzing

Based on legacy kAFL guide. Tested on Ubuntu 20.04.

For base installation, follow the [Getting Started](../README.md#getting-started) steps.

## Preparing Windows VM

### Preparing base image

1. [Download](https://www.microsoft.com/evalcenter/evaluate-windows) Windows installer ISO - `windows.iso`. I'll be using Windows Server 2019 Evaluation ISO (`17763.737.190906-2324.rs5_release_svc_refresh_SERVER_EVAL_x64FRE_en-us_1.iso`) from now on.
2. `qemu-img create -f qcow2 windows.qcow2 50G` - create QEMU hard drive image for Windows.
3. `./kAFL/qemu-5.0.0/x86_64-softmmu/qemu-system-x86_64 -machine q35 -enable-kvm -m 1024 -hda ./windows.qcow2 -cdrom ./windows.iso` - install Windows.
4. Install everything you need to the VM. It seems that currently QEMU creates NAT network for VM by default which gives you network access to the host as well as to the Internet which may be useful.
5. Shutdown the VM (`shutdown /s /t 0`).

### Preparing fuzzing snapshot

1. `qemu-img create -f qcow2 -b ./windows.qcow2 overlay_0.qcow2` - create overlay hard drive image which is based on `windows.qcow2` hard drive. Note that `windows.qcow2` can not be moved anywhere from this point, else you will need to manually correct `snapshot.qcow2` file using `qemu-img`.
2. Prepare loader binary. Generally you only need to do `./install.sh targets` in kAFL directory and use `targets/windows_x86_64/bin/loader/loader.exe`. Note that it may not build Windows targets by default, you need to install Mingw libraries first, as `install.sh` will suggest.
3. Copy loader binary to the VM. You can mount snapshot disk for that purpose: `mkdir mnt && sudo modprobe nbd && sudo qemu-nbd --connect=/dev/nbd0 ./overlay_0.qcow2 && sleep 1 && sudo mount /dev/nbd0p2 ./mnt && cp ./loader.exe ./mnt && umount ./mnt && sudo qemu-nbd --disconnect /dev/nbd0 && rmdir ./mnt`
4. Launch snapshot VM without network (`./kAFL/qemu-5.0.0/x86_64-softmmu/qemu-system-x86_64 -machine q35 -enable-kvm -m 1024 -hda ./overlay_0.qcow2 -net none`)
5. Run `loader.exe` in VM. You should see in QEMU output `Creating snapshot <kafl>` and eventually `Done. Shutting down..`. It is probable that everything will freeze at this point. Actually, only desktop manager is freezed, just switch to other console (Ctrl+Alt+F3), login, `sudo killall -9 qemu-system-x86_64`, switch back (Ctrl-Alt-F1).
6. Check that snapshot is created: `qemu-img info ./overlay_0.qcow2`

Congratz, at this point you have snapshot that is ready to be used with kAFL. To test it you can... (see next part).

## Fuzzing

At this point you will need work directory: `mkdir work`

### Obtaining driver virtual address range

`kafl_info.py` script is used for this purpose with special `info` payload binary. This binary is fed to the snapshot, is run in it by the loader and outputs driver "memory map" in a way.

1. `./kAFL/kAFL-Fuzzer/kafl_info.py -work_dir ./work -vm_dir . -mem 1024 -agent kAFL/targets/windows_x86_64/bin/info/info.exe` - note that we are passing `-mem` option here.

You will get a list like this:
```
...
0xfffff801ecf00000      0xfffff801ecf18000      lltdio.sys
0xfffff801ecf20000      0xfffff801ecf3b000      rspndr.sys
0xfffff801ecf40000      0xfffff801ecf65000      bowser.sys
0xfffff801ecf70000      0xfffff801ecf8a000      mpsdrv.sys
...
```

Find the driver that you want to fuzz there and remember two corresponding addresses.

#### Troubleshooting

This is the first point where you pass VM to kAFL instead of working with it directly. As a consequence, different errors may occur.

* `[ERROR]   QEMU-PT executable does not exists` - fix path to QEMU in kAFL/kAFL-Fuzzer/kafl.ini (absolute path is prefferable).
* `[FATAL] Failed to launch Qemu, please see logs. Error: [Errno 104] Connection reset by peer` - QEMU failed to start your VM. Usually it means there is parameter mismatch from your `qemu-system-x86_64` command and the one kAFL is using. Run `kafl_info.py` again with `-v --debug` arguments added and check `./work/debug.log` afterwards. Most probably there is mismatch in `-cpu` or `-machine` or `-m` option. Another possibility is that you forgot to create snapshot with `-net none` and now there is hanging PCI device since kAFL uses `-net none` by default.

### Fuzzing

1. Create seed directory: `mkdir seed && echo 0123456789abcdef > seed/0`
2. Modify fuzzer binary as you need and compile it. For Windows, you can modify `kAFL/targets/windows_x86_64/src/fuzzer/vuln_test.c` - change it so it will call your target driver properly. After that, compile it again by calling `./install.sh targets`
3. `./kAFL/kAFL-Fuzzer/kafl_fuzz.py -work_dir ./work --purge -seed_dir ./seed -vm_dir . -mem 1024 -ip0 0xfffff801ec850000-0xfffff801ec915000 -agent kAFL/targets/windows_x86_64/bin/fuzzer/vuln_test.exe` - start fuzzing! (You may want to add `--purge` option too here).
4. (optional) In another console, `./kAFL/kAFL-Fuzzer/kafl_gui.py ./work/`.

#### Troubleshooting

For other problems, run `kafl_fuzz.py` with `-v --debug` arguments and observer `./work/debug.log`.
