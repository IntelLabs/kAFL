# Using Nyx htools + sharedir for OS Fuzzing

The kAFL/Nyx `sharedir` option replaces the `agent` option in kAFL v0.2. The
old `agent` was required to be a single binary resulting in all kind of fancy
packaging approaches. With the sharedir option, the 'loader' can be a simple
shell script which in turn loads additional components via hypercalls
transparent to the target.

_TODO_: The Nyx htools are not currently integrated but must be sourced separately from [Nyx/packer](https://github.com/nyx-fuzz/packer).

To avoid frequent modifications to the target VM image, we use a minimal fixed
`loader.sh` integrated in the boot image. The `loader.sh` has the single purpose
to load a second stage loader script, dubbed `agent.sh` below. All actual
harness setup and execution is performed in this second stage.

## Create Linux VM Image

Create Linux VM image using regular (non-patched) Qemu.

For initial hello world it is recommended to use a recent Linux version.
Currently most testing is done with Ubuntu 20.04.

Consider using the same for host and guest to avoid problems with
cross-compiling agent binaries.

Activate the serial console and disable kASLR / PTI in Linux, e.g.

```
sudo tee -a /etc/default/grub << HERE
GRUB_CMDLINE_LINUX_DEFAULT=""
GRUB_CMDLINE_LINUX="nokaslr console=ttyS0 oops=panic nopti mitigations=off spectre_v2=off"
GRUB_TIMEOUT_STYLE=menu
GRUB_TIMEOUT=1
GRUB_DISABLE_RECOVERY=true
HERE
update-grub
```

## Deploy Loader Script

1. Mount VM image

```
sudo bash
modprobe nbd
qemu-nbd -c /dev/nbd0 $TARGET/image.qcow2
mount /dev/nbd0p1 /mnt/
```
 
2. Deploy loader components

```
cd ~/kafl
mkdir /mnt/fuzz
cp ~/kafl/targets/linux_x86_64/loader.sh /mnt/fuzz/
cp ~/kafl/targets/linux_x86_64/bin/htools/hget /mnt/fuzz/
chmod a+x /mnt/fuzz/*
```

3. Activate loader.sh on @reboot

The manual snapshot via LOCK hypercall still needs some fixing. Instead, we will
manually launch the loader.sh via cron. Make sure you have cron instaled in the
guest.

```
echo "@reboot root /fuzz/loader.sh" >> /mnt/etc/crontab
```

4. Unount and disconnect VM image (`important!`)

```
umount /mnt
qemu-nbd -d /dev/nbd0
```


## Prepare sharedir and launch VM

1. Prepare the sharedir. We include the vulnerable test driver
   `kafl_vuln_test.ko` and the corresponding fuzzer agents.

```
mkdir ~/sharedir
cp ~/kafl/target/linux_x86_64/bin/htools/* ~/sharedir/
cp ~/kafl/tests/test_cases/simple/linux_x86-64/kafl_vuln_test.ko ~/sharedir/
cp ~/kafl/targets/linux_x86_64/bin/fuzzer/kafl_vuln_test ~/sharedir/
cp ~/kafl/targets/linux_x86_64/bin/fuzzer/hprintf_test ~/sharedir/
cp ~/kafl/targets/linux_x86_64/agent.sh ~/sharedir/
```

Review `loader.sh` and `agent.sh` to understand the startup flow. The main
secret ingredient here is `hget`, which issues a hypercall to fetch a file from
`$sharedir` and stores it locally inside the guest. This way, the VM can fetch
all and any other components from sharedir at runtime.

2. Selecting the target IP range

kAFL requires you to select a reasonable IP range for tracing + decoding. While
it is still possible to supply this range using -ip<N> parameter, the
recommended option for targets such as Linux is to set the filter range(s) as
part of fuzzer initialization inside the guest.

The provided example uses a combination of `hinfo` and `hrange` tools to
accomplish this for the `kafl_vuln_test` sample. `hinfo` corresponds to the
original kAFL `info` agent and simply dumps the IP ranges of all loaded kernel
modules. `hrange` takes a list of IP ranges and configures them using
hypercalls. A possible use can be seen in `agent.sh`:

```
# dump all info to stdout (loader.sh redirects this to hcat!)
hinfo
# grep for target module and pipe ranges to hrange
hinfo |grep kafl_vuln|awk '{print NR-1":"$1}'|xargs hrange 
```

Review the source code for usage and setting further/custom filter ranges.


3. Launch VM in the Fuzzer


```
python3 ~/kafl/kafl_fuzz.py \
	--purge -p 1 -D -redqueen \
	-vm_image $TARGET/image.qcow2 \
	-mem 512 \
	-work_dir /dev/shm/kafl_ubuntu \
    -seed_dir ~/seeds/
	-sharedir ~/sharedir/
```

By default, the serial output is now logged to `$workdir/qemu_serial_<N>.log`.
The example scripts also make ample use of `hcat`, a simple frontend to
`hprintf()` which can be used to send printf strings directly to the python
frontend.

If the example does not work immediately, review these output messages together
with the shell scripts and agent code. Also consider switching to the more
verbose `hprintf_test` agent.


## Notes

- At any point in time, the image can be launched with regular/unpatched Qemu.
  The special kAFL/Nyx hypercalls will not work in this mode and the `hget/hcat`
  tools will simply exit with an error.

- The `htools` are intended as a simple baseline to bootstrap different fuzzing scenarios.
  Some of these tools can be used outside the kAFL environment, e.g. hinfo will
  still dump the kernel modules' IP ranges. 

  You may need to deploy your own / additional tools to extract special address
  ranges, functions to hook etc.

- Files downloaded into the guest still need to be executable there.  In
  particular, the `kafl_vuln_test.ko` will typically fail if it is not compiled
  for the kernel running inside the VM. The htools and fuzzer agents are simple
  enough to just work on most Linux systems, but more complex agents require
  static linking or installing the required runtime libraries inside the guest VM.

- Nyx will automatically snapshot the target VM when it encounters the first
  `NEXT_PAYLOAD` hypercall from the fuzzing main loop. This means it is okay to
  have a longer startup / preparation phase before actual fuzzing. Additional VM
  instances (`kafl_fuzz.py -p`) are started only after the initial snapshot is
  done and will directly resume from the snapshot.

- kAFL currently prints status messages to the main console even when its Qemu
  instances may still be in waiting state due to VM bootup / snapshotting.

