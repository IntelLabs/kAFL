# kAFL: HW-assisted Feedback Fuzzer for x86 VMs

kAFL is a fast guided fuzzer for the x86 VM. It is easily adapted for anything
that executes as Qemu/KVM guest, including BIOS, custom kernels and full-blown
VM images.

kAFL now leverages the Qemu/KVM backend from [Nyx](https://nyx-fuzz.com).

## Features

- kAFL uses Intel VT, Intel PML and Intel PT to achieve efficient execution,
  snapshot reset and coverage feedback for greybox or whitebox fuzzing scenarios.
  It allows to run many x86 FW and OS kernels with any desired toolchain and
  minimal code modifications.

- The kAFL-Fuzzer is written in Python and designed for parallel fuzzing with
  multiple Qemu instances. It uses an AFL-like fuzzer engine and easily extended
  to integrate custom mutators, analysis and tracing stages.

- kAFL integrates the Radamsa fuzzer as well as Redqueen and Grimoire extensions.
  Redqueen uses VM introspection to extract runtime inputs to conditional
  instructions, overcoming typical magic byte and other input checks.  Grimoire
  attempts to identify keywords and syntax from fuzz inputs in order to generate
  more clever large-scale mutations.


## Getting Started

kAFL uses multiple external components. You can use `west` to download them.
Check `~/kafl/west.yml` for defining local forks or branches:

```
$ pip3 install west
$ git clone $this_repo ~/kafl
$ west init -l ~/kafl
$ west update -k
```

kAFL includes an install.sh helper to automate installation. Review the detailed
steps inside this script if you run into trouble installing the components:

```
$ cd ~/kafl
$ ./install.sh deps     # check platform and install dependencies
$ ./install.sh perms    # allow current user to control KVM (/dev/kvm)
$ ./install.sh qemu     # download, patch and build Qemu
$ ./install.sh radamsa  # download, patch and build radamsa plugin
```

It is safe to re-execute any of these commands after failure,
for example if not all dependencies could have been downloaded.


If you do not have the modified kAFL kernel installed yet, you can follow the
steps in Nyx/KVM repo or use the below steps to generate a generic Debian kernel
package:

```
$ west update kvm
$ ./install.sh linux    # download, patch and build Linux
$ sudo dpkg -i linux-image*kafl+_*deb
$ sudo reboot
```

After reboot, make sure the new kernel is booted and PT support is detected by KVM:

```
$ dmesg|grep KVM
 [KVM-NYX] Info:   CPU is supported!
```

Lauch `kAFL-Fuzzer/kafl_fuzz.py` to verify all python dependencies are met. You
should be able to get a help message with all the config options:

```
$ python3 ~/kafl/kAFL-Fuzzer/kafl_fuzz.py -h
```

I case of errors, you may have to hunt down some python dependencies that did
not install correctly (try the corresponding package provided by your
distribution!), or set the correct path to the Qemu binary in
`kAFL-Fuzzer/kafl.ini`.


## Available Sample Targets

Once the above setup is working, you may try one of the available samples to get
started. For this purpose, please consider the supplied helper scripts and
READMEs as your hands-on "getting started" guides:

```
~/kafl/
  - targets/uefi_ovmf_64/{README.md,compile.sh}    - fuzz UEFI/OVMF and EFI apps
  - targets/zephyr_x86_32/{README.rst,compile.sh}  - fuzz Zephyr (ELF images)
  - targets/{linux,windows,macOS}\*                - fuzz full VMs (snapshots)
```

Note that these scripts and notes were confirmed to work at some point, but we
are not in a position to provide fully tested versions at all times.

## Visibility / Debug

The `kafl_fuzz.py` application is not meant to execute interactively and does not
provide much output beyond major errors. Instead, the status and statistics are
logged directly to the workding directory where they can be inspected with
separate tools:

```
/path/to/workdir/
  - corpus/       - corpus of inputs, sorted by execution result
  - metadata/     - metadata associated with each input
  - stats         - overall fuzzer status
  - slave_stats_N - individual status of each slave
  - debug.log     - detailed logging (activate with -v)
```

Most of the status/state files are stored as `msgpack`. You can use
`kAFL-Fuzzer/tools/mcat.py` to dump their content.

A more intuitive user interface can be started like this:

```
$ python3 ~/kafl/kAFL-Fuzzer/kafl_gui.py $workdir
```

Or use the plot tool to watch as the corpus grows:

```
$ python3 ~/kafl/kAFL-Fuzzer/kafl_plot.py $workdir
$ python3 ~/kafl/kAFL-Fuzzer/kafl_plot.py $workdir ~/graph.dot
$ xdot ~/graph.dot
```

kAFL also records some basic stats to plot progress over time:

```
$ gnuplot -c ~/kafl/tools/stats.plot $workdir/stats.csv
```

To obtain detailed coverage analysis, you can post-process a given workdir using
`kAFL-Fuzzer/kafl_cov.py`. This also creates a CSV file to plot discovered edges
over time. An example usage can be is provided for the UEFI target:

```
$ ./targets/uefi_ovmf_64/compile.sh cov $workdir
```

To replay a specific payload or trace its execution in GDB, take a look at
`kAFL-Fuzzer/kafl_debug.py`.


## Further Reading

* Step-by-step guides for [Linux](docs/linux_tutorial.md) and [Windows](docs/windows_tutorial.md)
* [Userspace fuzzing with sharedir](docs/sharedir_tutorial.md)
* [kAFL/Nyx hypercall API documentation](docs/hypercall_api.md)
* Papers and background at [nyx-fuzz.com](https://nyx-fuzz.com)

