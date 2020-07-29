# kAFL: Hardware-Assisted Feedback Fuzzing for OS Kernels

This Readme is adopted from the original kAFL release. The described flow
creates a regular Qemu VM image with a snapshot that is automatically loaded and
restored as part of kAFL fuzzing.

This "VM mode" fuzzing is now just one of the ways that kAFL can be used to
target full-blown OS installations such as Windows. The alternative "direct
kernel boot" (-kernel/-initrd) will typically work better due to the much smaller
memory footprint and easy parallelization (-p).


## Setup

This is a short introduction on how to setup kAFL to fuzz Linux kernel components.

### Download kAFL and install necessary components

```
$ git clone https://github.com/IntelLabs/kAFL.git
$ cd kAFL
$ chmod u+x install.sh
$ sudo ./install.sh
$ sudo reboot
```

### Setup VM

* Create QEMU hard drive image:

```
$ qemu-img create -f qcow2 linux.qcow2 20G
```

* Retrieve an ISO file of the desired OS and install it inside a VM (in this case Ubuntu 16.04 server):

```
$ wget -O ~/ubuntu.iso http://de.releases.ubuntu.com/16.04/ubuntu-16.04.3-server-amd64.iso
$ qemu-system-x86_64 -machine q35 -cpu host -enable-kvm -m 512 -hda linux.qcow2 -cdrom ~/ubuntu.iso -usbdevice tablet
```

* Download kAFL and compile the loader agent:

```
git clone https://github.com/RUB-SysSec/kAFL.git ~/kafl
cd ~/kafl/kAFL-Fuzzer/targets/linux_x86_64
bash compile.sh
```

* Shutdown the VM

### Prepare VM for kAFL fuzzing

* On the host: Create Overlay and Snapshot Files:

```
mkdir ~/kafl/snapshot && cd ~/kafl/snapshot
qemu-img create -b /absolute/path/to/hdd/linux.qcow2 -f qcow2 overlay_0.qcow2
qemu-img create -f qcow2 ram.qcow2 512
```

* Start the VM using QEMU-PT.  Note that if you change the platform
  configuration here to change the machine type or add a NIC, you may also have
  to fix the commandline used in common/qemu.py where the snapshot is loaded for
  fuzzing.

```
cd ~/kafl
./qemu-4.0.0/x86_64-softmmu/qemu-system-x86_64 \
	-hdb ~/kafl/snapshot/ram.qcow2 \
	-hda ~/kafl/snapshot/overlay_0.qcow2 \
	-machine q35 -serial mon:stdio -net none -enable-kvm -m 512
```

* (Optional) Install and load the vulnerable Test Driver inside the guest:

```
cd ~/kafl/tests/test_cases/simple/linux_x86-64/
chmod u+x load.sh
sudo ./load.sh
```

* Execute `loader` binary inside the guest. This will freeze your VM and cause
  Qemu to create a snapshot named "kafl" inside the image files. When resuming
  this snapshot on subsequent executions, the loader will perform a handshake
  with kAFL and launch the desired kAFL agent binary:

```
cd ~/kafl/
./install.sh targets
sudo targets/linux_x86_64/bin/loader/loader
```

* Switch to the QEMU management console and create a snapshot
  (Obsolete! Snapshot is automatically created as part of the KAFL_LOCK hypercall)

```
# press CTRL-a + c
savevm kafl
q 
```

To use an image in parallel fuzzing mode (-p N), create the corresponding
number of overlay files for launch via common/qemu.py: `snapshot/overlay_<0...N>.qcow2`.

## Fuzz a Target

### Compile and configure kAFL components

* Edit `~/kafl/kAFL-Fuzzer/kafl.ini` to ensure `qemu_kafl_location` points to the customized
  qemu build, .e.g. `~/kafl/qemu-5.0.0/x86_64-softmmu/qemu-system-x86_64`.

* Make sure agents are compiled on the host:

```
cd ~/kafl/targets/linux_x86_64
bash ./compile.sh
```

* Use the `info` agent to retrieve address ranges of loaded drivers inside the guest:

```
cd ~/kafl/
python3 kAFL-Fuzzer/kafl_info.py \
	-vm_dir snapshot/ \
	-vm_ram snapshot/ram.qcow2 \
	-agent targets/linux_x86_64/bin/info/info \
	-mem 512 -v
```

### Start Fuzzing!


```
cd ~/kafl/
python3 kAFL-Fuzzer/kafl_fuzz.py \
	-vm_ram snapshot/ram.qcow2 \
	-vm_dir snapshot \
	-agent targets/linux_x86_64/bin/fuzzer/kafl_vuln_test \
	-mem 512 \
	-seed_dir /path/to/seed/directory \
	-work_dir /path/to/working/directory \
	-ip0 0xffffffffc0287000-0xffffffffc028b000 -v --purge
```

The value `ip0` is the address range of the fuzzing target.
