# kAFL: HW-assisted Feedback Fuzzer for x86 VMs

kAFL/Nyx is a fast guided fuzzer for the x86 VM. It is great for anything that
executes as Qemu/KVM guest, in particular x86 firmware, kernels and full-blown
operating systems.

kAFL now leverages the greatly extended and improved [Nyx backend](https://nyx-fuzz.com).

## Features

- kAFL/Nyx uses Intel VT, Intel PML and Intel PT to achieve efficient execution,
  snapshot reset and coverage feedback for greybox or whitebox fuzzing scenarios.
  It allows to run many x86 FW and OS kernels with any desired toolchain and
  minimal code modifications.

- The kAFL-Fuzzer is written in Python and designed for parallel fuzzing with
  multiple Qemu instances. kAFL follows an AFL-like design but is easy to
  extend with custom mutation, analysis or scheduling options.

- kAFL integrates the Radamsa fuzzer as well as Redqueen and Grimoire extensions.
  Redqueen uses VM introspection to extract runtime inputs to conditional
  instructions, overcoming typical magic byte and other input checks. Grimoire
  attempts to identify keywords and syntax from fuzz inputs in order to generate
  more clever large-scale mutations.

For details on Redqueen, Grimoire, IJON, Nyx, please visit [nyx-fuzz.com](https://nyx-fuzz.com).

## Getting Started

### 1. Create a Workspace

To get started, checkout the `workspace` branch and initialize as a new
project workspace:

```shell
git clone --single-branch -b workspace git@github.com:IntelLabs/kAFL.git ~/work
cd ~/work
make env       # create and activate environment
```

This uses [pipenv](https://pypi.org/project/pipenv/) to create a Python
environment and deploys [west](https://docs.zephyrproject.org/latest/guides/west/) for managing
sub-repositories (See also: [working with west](README.md#working-with-west).
kAFL will be downloaded as first sub-project to `~/work/kafl`.

You can exit the environment with `exit` and re-activate at any time using `make env`.

### 2. Fetch and Build Components

On supported Ubuntu or Debian distribution, the included `kafl/install.sh` script can
be used to build all userspace components. Note that this script uses `sudo`
to deploy any system dependencies with `apt-get`. It will also ensure that the
current user has access to `/dev/kvm` by optionally creating a new group and
adding the user to it.

```shell
make update   # pull or update sub-components
make install  # build or rebuild components
```

In case of errors or unsupported distributions, please review the indivudal
steps in `Makefile` and `kafl/install.sh`.

### 3. Host kAFL Kernel

kAFL uses the modified `KVM-Nyx` host kernel for efficient PT tracing and
snapshots. For Debian-based distribution, you can use a
[prebuild release](https://github.com/IntelLabs/kafl.linux/releases)
of the _KVM-Nyx_ host kernel (not SDV!).

```
sudo dpkg -i linux-image-5.10.73-kafl*_amd64.deb
```

Alternatively, the below steps download, build and install a custom kernel
package based on your current kernel config in `/boot/config-$(uname -r)`:

```shell
west update host_kernel    # (not active by default)
./kafl/install.sh kvm      # uses your current config from /boot
sudo dpkg -i kafl/nyx/linux-image*kafl+_*deb
sudo reboot
```

After reboot, make sure the new kernel is booted and KVM-NYX confirms that PT is
supported on this CPU:

```shell
dmesg|grep KVM
> [KVM-NYX] Info:   CPU is supported!
```

### 4. (Optional) Lauch `kafl_fuzz.py`

After activating the workspace with `make env`, the kAFL entry points and
scripts will be made available in your PATH. Launch the fuzzer without options
to verify the basic system setup. You should see a help message with various
possible configuration options:

```shell
kafl_fuzz.py --help
```

I case of errors, you may have to hunt down some python dependencies that did
not install correctly. Try the corresponding packages provided by your
distribution and ensure that a correct path to the Qemu-Nyx binary is provided
in your local [kafl.yaml](kafl.yaml).


## Available Example Targets

Download the optional examples project for getting started with kAFL:

```
make env
west update -k examples
```

The following examples are suitable as out-of-the-box test cases:

- Zephyr hello world. Follow the steps in
  [Zephyr/README](https://github.com/IntelLabs/kafl.targets/tree/master/zephyr_x86_32)

__TODO:__ other examples need to be updated again - any help appreciated

  - UEFI / EDK2
  - Linux kernel and userspace
  - Windows + OSX


## Understanding Fuzzer Status

The `kafl_fuzz.py` application is not meant to execute interactively and does
not provide much output beyond basic status + errors. Instead, all status and
statistics are written directly to a `working directory` where they can be
inspected with separate tools.

 The `workdir` must be specified on startup and will usually be overwritten.
Example directory structure:

```
/path/to/workdir/
 - imports/       - staging folder for supplying new seeds at runtime
 - corpus/        - corpus of inputs, sorted by execution result
 - metadata/      - metadata associated with each input
 - stats          - overall fuzzer status
 - worker_stats_N - individual status of Worker <N>
 - serial_N.log   - serial logs for Worker <N>
 - hprintf_N.log  - guest agent logging (--log-hprintf)
 - debug.log      - debug logging (max verbosity: --log --debug)

 - traces/        - output of raw and decoded trace data (kafl_fuzz.py -trace, kafl_cov.py)
 - dump/          - staging folder to data uploads from guest to host

 - page_cache.*   - guest page cache data
 - snapshot/      - guest snapshot data
 - bitmaps/       - fuzzer bitmaps
  [various shared memory and socket files]
```

The fuzzer stats and metadata files are in `msgpack` format. Use the included `mcat.py`
to dump their content. A more interactive interface can be launched like this:

```
$ kafl_gui.py $workdir
```

Or use the `plot` tool to see how the corpus is evolving over time:

```
$ kafl_plot.py $workdir
$ kafl_plot.py $workdir ~/graph.dot
$ xdot ~/graph.dot
```

kAFL also records basic status in stats.csv to plot performance over time:

```
$ gnuplot -c ~/work/kafl/scripts/stats.plot $workdir/stats.csv
```

## Coverage and Debug

To obtain detailed coverage data, you need to collect PT traces and decode them.
Collecting binary PT traces is reasonably efficient during fuzzer runtime, by using
`kafl_fuzz.py --trace`. Given an existing workdir with corpus, `kafl_cov.py` tool
will optionally re-run the corpus to collect missing PT traces and then decode
them to the list of seen edge transitions. This file can be further processed
with tools like Ghidra. For instance, for the Zephyr example:

```
$ ./examples/zephyr_x86_32/run.sh cov /dev/shm/kafl_zephyr/
$ ls /dev/shm/kafl_zephyr/traces/
$ ./kafl/scripts/ghidra_run.sh /dev/shm/kafl $path/to/zephyr.elf kafl/scripts/ghidra_cov_analysis.py
```

Finally, `kafl_debug.py` contains a few more execution options such as launching Qemu with a single
payload and gdbserver enabled, or tracing the same payload many times to analyze non-deterministic behavior.


## Working with West

West aims to provide a [more flexible
alternative](https://docs.zephyrproject.org/latest/guides/west/why.html) to repo
management. It stays mostly out of your way as long as you avoid the `import`
feature.

To work on one of the checked out repos, fetch the upstream git refs and switch
to a custom branch. To work with your own fork, change the manifest URL or just add
your fork as a remote:

```
cd ~/work/examples
git remote -v                    # show defined remotes, e.g. 'github'
git fetch github                 # fetch refs from 'github' remote
git switch -c mybranch           # create + switch to own branch
git remote add myrepo <repo_url> # add own repo as git remote
git push -u myrepo mybranch      # push own branch to own repo
```

When running `west update -k`, west will keep your branches and changes intact,
or print a message on how to restore them. If you do not restore changes or
commit them to a branch/fork, local modifications will eventually be lost(!).
See [west basics](https://docs.zephyrproject.org/latest/guides/west/basics.html) to learn more. 

Check out the [west
manifest](https://docs.zephyrproject.org/latest/guides/west/manifest.html)
(`manifest/west.yml`) to define your own repositories and revisions.


## Further Reading (need updating!)

* Step-by-step guides for [Linux](docs/linux_tutorial.md) and [Windows](docs/windows_tutorial.md)
* [Userspace fuzzing with sharedir](docs/sharedir_tutorial.md)
* [kAFL/Nyx hypercall API documentation](docs/hypercall_api.md)
* Papers and background at [nyx-fuzz.com](https://nyx-fuzz.com)

