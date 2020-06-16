# HW-assisted Feedback Fuzzing for x86 Kernels and Firmware

This is a fork of the kAFL kernel fuzzer. In cooperation with the original
developers, this can be used to explore VM-based fuzzing and target
x86-compatible low-level SW.


## How is it different?

- kAFL uses Qemu/KVM and Intel PT to provide fast execution and coverage
  feedback. This allows to run many x86 FW and OS kernels with any desired
  toolchain and without major modifications.

- Instead of modeling an API like e.g. Syzkaller or Peach, kAFL provides a more
  low-level hypercall API that can be used by the Tester to inject fuzz input at
  the desired subsystem and flexibly raise error conditions back to the fuzzer.

- kAFL uses a modular design, using a (homebrew) python fuzzer that can talk to
  multiple Qemu instances via SHM and pipes. It is designed for parallel and
  persistent mode fuzzing but also easy to adapt to special cases, such as
  observing non-determinism and resetting on demand.

- Redqueen and Grimoire are new generic fuzzer extensions implemented on top of
  kAFL. Redqueen uses VM introspection to extract runtime inputs to conditional
  instructions, overcoming typical magic byte and other input checks.  Grimoire
  attempts to identify keywords and syntax from fuzz inputs in order to generate
  more clever large-scale mutations.


## Getting Started

Installation requires multiple components, some of which can depend on Internet
connectivity and defaults of your distribution / version. It is recommended to
install step by step and manually investigate any reported errors:

```
$ git clone $this_repo ~/kafl

$ cd ~/kafl
$ ./install.sh deps     # check platform and install dependencies
$ ./install.sh perms    # allow current user to control KVM (/dev/kvm)
$ ./install.sh qemu     # download, patch and build Qemu
$ ./install.sh linux    # download, patch and build Linux
```

It is safe to re-execute any of these commands after failure, for example
if not all dependencies could have been downloaded.

The final step does not automatically install the new Linux kernel but only gives
some default instructions. Install according to your preference/distribution
defaults, or simply follow the suggested steps:

```
$ ./install.sh note
```

After reboot, make sure the new kernel is booted and PT support is detected by KVM:

```
$ sudo reboot
$ dmesg|grep VMX
 [VMX-PT] Info:   CPU is supported!
```

Lauch `kAFL-Fuzzer/kafl_fuzz.py` to verify all python dependencies are met. You
should be able to get a help message with the detailed list of parameters:

```
$ python3 ~/kafl/kAFL-Fuzzer/kafl_fuzz.py VM -h
$ python3 ~/kafl/kAFL-Fuzzer/kafl_fuzz.py Kernel -h
```

You may have to hunt down some python dependencies that did not install
correctly (try the corresponding package provided by your distribution!),
or set the correct path to the Qemu binary in `kAFL-Fuzzer/kafl.ini`.


## Available Sample Targets

Once the above setup is working, you may try one of the available samples to get
started. For this purpose, please consider the supplied helper scripts and
READMEs as your hands-on "getting started" guides:

```
~/kafl/
  - targets/uefi_ovmf_64/{README.md,compile.sh}    - fuzz UEFI/OVMF and EFI apps
  - targets/zephyr_x86_32/{README.rst,compile.sh}  - fuzz Zephyr (ELF images)
  - targets/{linux,windows,macOS}\*                - fuzz full VMs (snapshots)
  - tests/user_bench/{README.md,build.sh,run.sh}   - fuzz binutils (user apps)
```

Note that these scripts and notes were confirmed to work at some point, but we
are not in a position to provide fully tested "stable" releases. For samples
3 and 4, you may also refer to [kAFL ReadMe](doc/README.kAFL.md) and
[Redqueen Readme](doc/README.Redqueen.md).


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


## Contributions

kAFL, Redqueen & Grimoire were originally developed by:

```
Sergej Schumilo         <sergej@schumilo.de>
Cornelius Aschermann    <cornelius.aschermann@rub.de>
Robert Gawlik           <robert.gawlik@rub.de>
Tim Blazytko            <tim.blazytko@rub.de>
```

This project merges the respective released prototypes and adds various changes
in the hope that they are useful. Contributions are welcome.

Current developer(s):

```
Steffen Schulz <steffen.schulz@intel.com>
```
