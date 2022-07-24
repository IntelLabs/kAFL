# Getting Started with Linux Fuzzing

Based on legacy kAFL guide. Running on newer distributions may require minor
fixes to provided sample code.

For base installation, follow the [Getting Started](../README.md#getting-started) steps.

## Preparing a Linux VM Image

### Option #1: Full VM Install (Manual)

1. Download Ubuntu 16.04 Installer iso as `ubuntu.iso`. Last verified working version:
   `wget -c -O ubuntu.iso https://releases.ubuntu.com/16.04/ubuntu-16.04.7-server-amd64.iso`

2.  Create QEMU hard drive image for Ubuntu.
    `qemu-img create -f qcow2 ubuntu.qcow2 20G`

3. Start VM and install Ubuntu:
   `qemu -machine q35 -enable-kvm -m 1024 -hda ./ubuntu.qcow2 -cdrom ./ubuntu.iso`

4. Inside the guest, clone the kAFL repository and build the Linux kAFL agents:
   `git clone https://github.com/IntelLabs/kAFL.git`
   `./install.sh targets`

5. Perform any other required setup and fix-ups
   
   update-grub: spectre_v2=off, mitigations=off, nopti, oops=panic, nokaslr, console=ttyS0
   sudo sysctl kernel.randomize_va_space=0 

6. Shutdown the VM.


### Option #2: Build from Filesystem (Automated)

Generating the VM image directly from a desired filesystem hierarchy helps with
automation and results in smaller image footprint.

The following snippets generate a minimal Ubuntu 16.04 root FS using
debootstrap, and enables the hello world (`kafl_vuln_test`) and filesystem
fuzzing test cases. Other distributions tend to have similar tools, e.g.
`febootstrap` on Fedora. You can also use `Busybox` to further reduce the memory
footprint of your harness.

1. Build Ubuntu 16.04 rootfs:

```
cd ~/kafl
TARGET=$(realpath targets/ubuntu_16.04)
mkdir -p $TARGET/rootfs
sudo debootstrap --arch=amd64 --variant=minbase --include vim,ssh \
     xenial $TARGET/rootfs/ http://archive.ubuntu.com/ubuntu/
```

2. Deploy the fuzz target and kAFL agent loader. We use the current host kernel
   version here so we don't have to worry about cross-compiling/porting any of
   these components.

```
./install.sh targets

# deploy a kernel of your choice
mkdir $TARGET/rootfs/lib/modules
sudo cp -a /lib/modules/$(uname -r)/ $TARGET/rootfs/lib/modules/
sudo cp -a /boot/*$(uname -r) $TARGET/rootfs/boot/

# deploy kAFL loader and any fuzzer/target dependencies
sudo cp targets/linux_x86_64/bin/loader/loader $TARGET/rootfs/loader
pushd tests/test_cases/simple/linux_x86-64
make
sudo cp kafl_vuln_test.ko $TARGET/rootfs/
popd

# prepare VM to launch hello world and FS fuzzer agents
sudo tee $TARGET/rootfs/etc/rc.local << HERE
> #!/bin/sh
> sysctl kernel.randomize_va_space=0
> modprobe loop
> modprobe vfat
> insmod /kafl_vuln_test.ko
> /loader
> HERE

# optionally set a root password for easy login/debug
sudo chroot $TARGET/rootfs/ passwd
```

3. Wrap the rootfs into a qemu image.

```
# last time need for sudo as we aggregate the rootfs to a regular file
sudo mkfs.ext4 -L '' -N 0 -d $TARGET/rootfs -e panic $TARGET/image.ext4 2G
qemu-img convert -f raw -O qcow2 $TARGET/image.ext4 $TARGET/image.qcow2
```

Note: Creating the image this way does not deploy a bootloader, so we have to launch
it using Qemu `-kernel` and `-initrd` options. Since the kAFL loader has been
setup in `/etc/rc.local`, booting the image will directly proceed to snapshot
creation.


### Preparing the Fuzzing Snapshot

Perform a final boot of the VM image to create a snapshot for fuzzing.

The Qemu configuration used when booting and creating the snapshot here must be
identical to the one used when restoring the snapshot later during fuzzing. This
is the last time to adjust RAM size, machine type and peripherals available to
the guest. Even simple things like a missing in the kernel commandline can make
the snapshot incompatible. Verify against the qemu commandline reported in the
logs (`kafl_fuzz.py -v`).

1. Create an overlay file for snapshot creation. We can copy this overlay to
   fuzz multiple VM instances in parallel.

```
qemu-img create -b $TARGET/image.qcow2 -F qcow2 -f qcow2 $TARGET/overlay_0.qcow2
```

2. Launch final VM configuration and execute kAFL `loader` to initiate the
   snapshot. If you followed the `debootstrap` path above, the following snipped
   uses the corresponding `-kernel/-initrd` direct boot options, will automatically
   launch the loader from `/etc/rc.local` and create a snapshot.

```
# Launch VM for final snapshot
qemu-5.0.0/x86_64-softmmu/qemu-system-x86_64 \
        -enable-kvm \
        -nographic \
        -net none \
        -machine q35 \
        -serial mon:stdio \
        -kernel $TARGET/rootfs/boot/vmlinuz-$(uname -r) \
        -initrd $TARGET/rootfs/boot/initrd.img-$(uname -r) \
        -hda $TARGET/overlay_0.qcow2 \
        -m 512 \
        -append "root=/dev/sda rw nokaslr console=ttyS0 oops=panic nopti mitigations=off spectre_v2=off"
```
 
You can verify that the snapshot was created and optionally create multiple copies for parallel fuzzing:

```
qemu-img info ./overlay_0.qcow2

for i in $(seq $(nproc)); do
    cp $TARGET/overlay_0.qcow2 $TARGET/overlay_$i.qcow2
done
```

## Fuzzing

kAFL must be launched with the virtual address range to be traced for coverage
feedback. It is recommended to set this range to the specific subsystem/code you
want to fuzz in order to minimize noise from other components (scheduling,
interrupts).

1. To obtain the guests drivers virtual address range, you can use
   `kafl_info.py` and `kAFL/targets/linux_x86_64/bin/info/info`. The script
   feeds the `info` binary to the loader where it will scan and output the current
   address ranges for all modules:

```
WORK=~/work; mkdir -p $WORK

./kAFL/kAFL-Fuzzer/kafl_info.py --purge \
	-vm_dir $TARGET \
	-mem 512 \
	-work_dir $WORK \
	-agent targets/linux_x86_64/bin/info/info
```

Example output :
```
[...]
0xffffffffc0022000-0xffffffffc0042000	psmouse
0xffffffffc0010000-0xffffffffc001a000	ahci
0xffffffffc0002000-0xffffffffc000a000	kafl_vuln_test
0xffffffff81000000-0xffffffff81a4aea0	Kernel Core
[...]
```

2. To fuzz the hello world sample, we set the PT filter range to the
   `kafl_vuln_test` module and launch the fuzzer with the corresponding agent:

```
SEEDS=~/seeds; mkdir -p $SEEDS
echo "abcdefg1234567890" > $SEEDS/seed

./kAFL-Fuzzer/kafl_fuzz.py --purge \
	-vm_dir $TARGET \
	-mem 512 \
	-agent targets/linux_x86_64/bin/fuzzer/kafl_vuln_test \
	-seed_dir $SEEDS \
	-work_dir $WORK \
	-ip0 0xffffffffc0002000-0xffffffffc000a000 -v
```

The view fuzzing progress, troubleshooting and making sense of the work dir
outputs, continue with the main guide (_TBD_).
See also: [README.md](kAFL#visibility--debug) and [Windows
Troubleshooting](docs/Windows_tutorial.md#troubleshooting)

