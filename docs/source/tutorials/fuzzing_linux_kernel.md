# Fuzzing the Linux Kernel

This example shows how to fuzz an OS kernel by implementing the kAFL agent
(harness) directly in the target.

This is useful for directly interfacing with low-level kernel interfaces,
or fuzzing during bootstrapping when no userspace is available.

It also has the benefit of not requiring any additional guest filesystem
setup or cross-compiling, as the harness is implemented directly in the kernel.


Instead of a silly hello world function, this example uses an existing kAFL
agent implemented for TDX guest kernel validation. We can enable an option to
perform input injection in the PCI MMIO/PIO reads, which will result in
interesting crashes when fuzzing PCI and VIRTIO initialization.

## 1. Download patched Linux kernel (or port to your preferred kernel)

This kernel branch implements a kAFL agent in arch/x86/kernel/. It offers
multiple options for input injection and a state machine to enable/disable
fuzzing at various points during kernel execution.

```
cd $EXAMPLES_ROOT/linux-kernel/
git clone -b kafl/fuzz-5.15-4 https://github.com/IntelLabs/kafl.linux.git linux-guest
```

## 2. Configure and build target kernel

Install build dependencies (depends on kernel .config):
```
sudo apt install gawk bison flex openssl libssl-dev libelf-dev lz4 dwarves
```

Use the provided example config to build a guest kernel with PCI/VIRTIO fuzzing
enabled:

```
cd linux-guest
cp ../config.vanilla.virtio .config
make -j$(nproc)
```

## 3. Start fuzzing!

Since the harness is built-in and auto-snapshots on first fuzzing input,
launching the fuzzer is as simple as booting the kernel:

```
kafl_fuzz.py  --purge -w /dev/shm/kafl \
	--redqueen --grimoire -D --radamsa \
	--kernel arch/x86/boot/bzImage \
	-t 0.1 -ts 0.01 -m 512 --log-crashes -p 2
```

Expected output:

```
    __                        __  ___    ________
   / /_____  _________  ___  / / /   |  / ____/ /
  / //_/ _ \/ ___/ __ \/ _ \/ / / /| | / /_  / /
 / ,< /  __/ /  / / / /  __/ / / ___ |/ __/ / /___
/_/|_|\___/_/  /_/ /_/\___/_/ /_/  |_/_/   /_____/
===================================================

<< kAFL Fuzzer >>

Warning: Launching without -seed_dir?
No PT trace region defined.
00:00:00:     0 exec/s,    0 edges,  0% favs pending, findings: <0, 0, 0>
Worker-00 Launching virtual machine...
/home/user/work/kafl/nyx/qemu/x86_64-softmmu/qemu-system-x86_64
        -enable-kvm
        -machine kAFL64-v1
        -cpu kAFL64-Hypervisor-v1,+vmx
        -no-reboot
        -display none
        -netdev user,id=mynet0
        -device virtio-net,netdev=mynet0
        -chardev socket,server,nowait,id=nyx_socket,path=/dev/shm/kafl/interface_0
        -device nyx,chardev=nyx_socket,workdir=/dev/shm/kafl,worker_id=0,bitmap_size=65536,input_buffer_size=131072
        -device isa-serial,chardev=kafl_serial
        -chardev file,id=kafl_serial,mux=on,path=/dev/shm/kafl/serial_00.log
        -m 512
        -kernel /home/user/work/examples/linux-kernel/linux-guest/arch/x86/boot/bzImage
        -append root=/dev/vda1 rw hprintf=4 nokaslr oops=panic nopti mitigations=off
        -fast_vm_reload path=/dev/shm/kafl/snapshot/,load=off
Worker-01 Launching virtual machine...
Invalid sharedir...
[QEMU-Nyx] Booting VM to start fuzzing...
Invalid sharedir...
[!] qemu-nyx: waiting for snapshot to start fuzzing...
WARNING: ATTEMPTING FAST GET for virtio
Worker-00 entering fuzz loop..
00:00:02: Got    1 from    0: exit=R, 5637/ 0 bits, 5637 favs, 4.56msec, 0.2KB (kickstart)
00:00:02: Got    2 from    0: exit=R, 261/605 bits, 743 favs, 5.55msec, 0.2KB (kickstart)
00:00:02: Got    3 from    0: exit=R, 2298/2785 bits, 2298 favs, 21.20msec, 0.2KB (kickstart)
00:00:02: Got    4 from    0: exit=R, 20/576 bits, 35 favs, 17.62msec, 0.2KB (kickstart)
00:00:02: Got    5 from    0: exit=R, 32/644 bits, 2072 favs, 11.99msec, 0.2KB (kickstart)
00:00:03: Got    6 from    0: exit=R,  0/14 bits,  0 favs, 15.52msec, 0.2KB (kickstart)
00:00:03: Got    7 from    0: exit=R,  0/ 5 bits,  0 favs, 19.62msec, 0.2KB (kickstart)
00:00:03: Got    8 from    0: exit=R,  0/ 3 bits,  0 favs, 4.49msec, 0.2KB (kickstart)
00:00:03: Got    9 from    0: exit=R,  0/ 1 bits,  0 favs, 12.25msec, 0.2KB (kickstart)
Worker-01 entering fuzz loop..
00:00:03: Got   10 from    0: exit=R, 42/3502 bits, 42 favs, 36.80msec, 0.2KB (kickstart)
00:00:03: Got   11 from    5: exit=K, 8667/ 0 bits,  0 favs, 98.15msec, 0.2KB (calibrate)
00:00:03: Got   12 from    0: exit=R,  5/1516 bits, 796 favs, 14.27msec, 0.2KB (kickstart)
00:00:03: Got   13 from    5: exit=R,  0/21 bits,  0 favs, 12.19msec, 0.2KB (calibrate)
00:00:03: Got   14 from    0: exit=R,  0/12 bits,  0 favs, 19.61msec, 0.2KB (kickstart)
00:00:03: Got   15 from    5: exit=R,  4/636 bits, 1132 favs, 6.54msec, 0.0KB (trim)
00:00:03: Got   16 from    5: exit=R,  0/272 bits,  0 favs, 2.50msec, 0.0KB (trim)
00:00:03: Got   17 from    5: exit=R,  0/79 bits,  0 favs, 0.26msec, 0.0KB (trim)
00:00:03: Got   18 from    5: exit=R,  0/395 bits,  0 favs, 4.81msec, 0.0KB (trim)
00:00:03: Got   19 from    5: exit=R,  0/247 bits,  0 favs, 8.41msec, 0.0KB (trim)
00:00:03: Got   20 from    5: exit=R,  0/670 bits,  0 favs, 4.44msec, 0.0KB (trim)
00:00:03: Got   21 from    0: exit=R,  0/ 4 bits,  0 favs, 14.56msec, 0.2KB (kickstart)
00:00:03: Got   22 from    5: exit=R,  0/ 1 bits,  0 favs, 14.25msec, 0.1KB (trim_center)
[...]
```

## 4. Next steps..

Look at the kernel source code and in particular at the implementation of the
different harness and input injection options defined in .config.

Be sure to read other documentation to understand the various options and
interpreting fuzzer output. Some hints (run in separate terminal):

```
kafl_gui.py $KAFL_WORKDIR
```

```
ls $KAFL_WORKDIR/corpus/
ls $KAFL_WORKDIR/logs/
```

For coverage reports, find out what PT filter ranges are used for the kernel image (they are auto-detected on startup and logged using `kafl_hprintf()` - try to launch with `--log-hprintf -p 1` instead of the above `--log-crashes` and look at `$workdir/hprintf_00.log`). Then use `kafl_cov.py` with `--resume` and same workdir + input directory. This will restore the VM snapshot and use the existing page_cache info to replay corpus payloads as faithfully as possible and dump PT trace info to `$workdir/traces/*bin.lz4`. The tool will also call `ptdump` on each trace to directly decode it to `$workdir/traces/*.txt.lz4`. For big corpuses, you can parallelize this process using `-p`. Example:

```
KAFL_CONFIG_FILE=kafl_config.yaml kafl_cov.py \
	-w /dev/shm/kafl --input /dev/shm/kafl \
	--kernel source/arch/x86/boot/bzImage \
	-ip0 ffffffff81000000-ffffffff83603000 \
	-ip1 ffffffff855ed000-ffffffff856e4000 \
	--resume -m 512 -t 2 -p 4
```

## 5. Known Issues

1) *[ERROR] Guest ABORT: Attempt to finish kAFL run but never initialized* - This
happens when the configured harness does not consume any inputs. For instance
when fuzzing PCI initialization functions without activating MMIO/PIO input
injection. Also, initialization phases may depend on each other, for instance,
fuzzing virtio-net initialization may be a no-op if previously performed PCI
scan did not detect any virtio-net devices. It helps to enable virtio-net in
Qemu.

2) *libxdc_decode_error* - This mainly seems to happen on dynamic code rewrite.
Linux does this in several places, for instance due to paravirtualization,
dynamic ftrace, jump label etc.

3) *qemu-system-x86_64: assertion error xyz* - Especially during virtio fuzzing,
the guest may do unexpected things to the host virtio emulation that can cause
Qemu to crash or leak memory. In most cases it is sufficient to disable the
assert.