# kAFL: Hardware-Assisted Feedback Fuzzing for OS Kernels

Blazing fast x86-64 VM kernel fuzzing framework with performant VM reloads for Linux, MacOS and Windows.

Published at USENIX Security 2017.

### Currently missing: 

- full documentation
- agents for macOS and Windows (except for our test driver)

## BibTex:
```
@inproceedings{schumilo2017kafl,
    author = {Schumilo, Sergej and Aschermann, Cornelius and Gawlik, Robert and Schinzel, Sebastian and Holz, Thorsten},
    title = {{kAFL: Hardware-Assisted Feedback Fuzzing for OS Kernels}},
    year = {2017},
    booktitle = {USENIX Security Symposium} 
}
```

## Trophies

- [Linux keyctl null pointer dereference](http://seclists.org/fulldisclosure/2016/Nov/76) (**CVE-2016-8650**)
- [Linux EXT4 memory corruption](http://seclists.org/fulldisclosure/2016/Nov/75)
- [Linux EXT4 denial of service](http://seclists.org/bugtraq/2016/Nov/1) 
- [macOS APFS memory corruption](https://support.apple.com/en-us/HT208221) (**CVE-2017-13800**)
- [macOS HFS memory corruption](https://support.apple.com/en-us/HT208221) (**CVE-2017-13830**)


## Setup

This is a short introduction on how to setup kAFL to fuzz Linux kernel components.

### Download kAFL and install necessary components
```
$ git clone https://github.com/RUB-SysSec/kAFL.git
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
$ qemu-system-x86_64 -cpu host -enable-kvm -m 512 -hda linux.qcow2 -cdrom ~/ubuntu.iso -usbdevice tablet
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

* Start the VM using QEMU-PT:

```
cd ~/kafl
./qemu-4.0.0/x86_64-softmmu/qemu-system-x86_64 \
	-hdb ~/kafl/snapshot/ram.qcow2 \
	-hda ~/kafl/snapshot/overlay_0.qcow2 \
	-machine pc-i440fx-2.6 -serial mon:stdio -enable-kvm -m 512
```

* (Optional) Install and load the vulnerable Test Driver:

```
cd ~/kafl/tests/test_cases/simple/linux_x86-64/
chmod u+x load.sh
sudo ./load.sh
```

* Execute loader binary which is in `~/kafl/targets/linux_x86_64/bin/loader/` as `root`. VM should freeze. Switch to the QEMU management console and create a snapshot:

```
# press CTRL-a + c
savevm kafl
q 
```

## Fuzz a Target

### Compile and configure kAFL components
* Edit `~/kafl/kAFL-Fuzzer/kafl.ini` (`qemu_kafl_location` to point to `~/kafl/qemu-4.0.0/x86_64-softmmu/qemu-system-x86_64`)

* Compile agents:

```
cd ~/kafl/targets/linux_x86_64
chmod u+x compile.sh
./compile.sh
```

* Retrieve address ranges of loaded drivers:

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
