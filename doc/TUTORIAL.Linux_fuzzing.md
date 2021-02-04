Refer to TUTORIAL.Installation.md first. Make sure that all necessary components (i.e. fuzzing agents) are installed on your VM host.

Based on README.kAFL.md. Tested on Ubuntu 20.04 host.

## Preparing Linux VM

### Preparing Base VM Image
1. [Download](https://releases.ubuntu.com/16.04/ubuntu-16.04.7-server-amd64.iso) Ubuntu 16.04 Installer iso - `ubuntu.iso`. Last verified working version (`https://releases.ubuntu.com/16.04/ubuntu-16.04.7-server-amd64.iso`).
2. `qemu-img create -f qcow2 ubuntu.qcow2 20G` - create QEMU hard drive image for Ubuntu.
3. Start VM `./kAFL/qemu-5.0.0/x86_64-softmmu/qemu-system-x86_64 -machine q35 -enable-kvm -m 1024 -hda ./ubuntu.qcow2 -cdrom ./ubuntu.iso` and install Ubuntu.
4. Clone the kAFL repository on the VM guest (`git clone https://github.com/IntelLabs/kAFL.git`) and install the targets (`./install.sh targets`).
5. Install everything else you need.
6. Shutdown the VM.

### Preparing Fuzzing Snapshot
1. `qemu-img create -f qcow2 -b ./ubuntu.qcow2 overlay_0.qcow2` - create overlay hard drive image which is based on `ubuntu.qcow2` hard drive. Note that `ubuntu.qcow2` can not be moved anywhere at this point, otherwise you will need to manually correct `snapshot.qcow2` file using `qemu-img`.
2. Launch snapshot VM without network: `./kAFL/qemu-5.0.0/x86_64-softmmu/qemu-system-x86_64 -machine q35 -enable-kvm -m 1024 -hda ./overlay_0.qcow2 -net none`.
3. Run loader binary (`./kAFL/targets/linux_x86_64/bin/loader/loader`) on the VM guest. You should see `Creating snapshot <kafl>` and `Done. Shutting down..` on the
QEMU console. Since this will freeze your QEMU VM instance, you need to force kill the QEMU VM process with `sudo killall -9 qemu-system-x86_64`.
4. Verify that the snapshot was created with `qemu-img info ./overlay_0.qcow2`.

## Fuzzing
At this point you will need a work directory (`mkdir work`).

### Obtaining Driver Virtual Address Range
To obtain the guests drivers virtual address range, you can use `kafl_info.py` and `kAFL/targets/linux_x86_64/bin/info/info`. The script feeds the `info` binary
to the snapshot that is run by the loader and outputs the virtual address ranges for the guest drivers. For that purpose, use `./kAFL/kAFL-Fuzzer/kafl_info.py -work_dir ./work -vm_dir . -mem 1024 -agent kAFL/targets/linux_x86_64/bin/info/info`.

You will get a list like this:
```
...
0xffffffffc0022000-0xffffffffc0042000	psmouse
0xffffffffc0010000-0xffffffffc001a000	ahci
0xffffffffc0002000-0xffffffffc000a000	libahci
0xffffffff81000000-0xffffffff81a4aea0	Kernel Core
...
```

Find the driver that you want to fuzz there and remember corresponding address range.

### Start Fuzzing
To start fuzzing, use:
```
./kAFL/kAFL-Fuzzer/kafl_fuzz.py \
	-vm_dir . \
	-agent ./kAFL/targets/linux_x86_64/bin/fuzzer/kafl_vuln_test \
	-mem 1024 \
	-seed_dir /path/to/seed/dir \
	-work_dir ./work \
	-ip0 <address_range> -v --purge
```

Make sure that the virtual memory size the VM guest is invoked with (`-mem <size>`) matches the size the VM image was created with, otherwise
the VM bootup via kAFL will result in errors.

## Troubleshooting and Errors
For troubleshooting and common errors, refer to [TUTORIAL.Windows_fuzzing.md](https://github.com/IntelLabs/kAFL/blob/master/doc/TUTORIAL.Windows_fuzzing.md)

