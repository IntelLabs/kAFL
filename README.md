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

1. We use [west](https://docs.zephyrproject.org/latest/guides/west/) to keep
   a handle on repositories, and [pipenv](https://pypi.org/project/pipenv/) to
   manage Python dependencies. Simply create a new directory and initialize it as
   your west workspace and Python venv as follows:

```
$ pip3 install pipenv
$ mkdir -p ~/work; cd ~/work
$ pipenv install west        # create a new venv and add west
$ pipenv shell               # enter venv for further install

# initialize west workspace using the desired kAFL repo + branch (i.e. _this_ repo + branch!)
$ west init --mr $this_branch -m $this_url

$ west update -k     # update all repos in manifest
$ west list          # show all repos in manifest
```

See [working with west](README.md#working-with-west) for how to work on the checked out repos.

1. kAFL includes an `install.sh` helper to automate installation and building of
   dependencies. These should work on any recent (2020/21) Ubuntu or Debian:

```
$ cd ~/work/kafl
$ ./install.sh deps     # check platform and install dependencies
$ ./install.sh perms    # allow current user to control KVM (/dev/kvm)
$ ./install.sh qemu     # download, patch and build Qemu
$ ./install.sh radamsa  # download, patch and build radamsa plugin
```

It is safe to re-execute any of these commands on errors,
for example if some dependencies could not be downloaded.
For other problems, review the individual steps inside this script.

1. (Optional) Also install kAFL itself into the Python venv so that you can
   easily launch it from your target/project folders:

```
$ cd ~/work/kafl
$ pipenv shell      # enter python venv
$ pip install -e .  # editable installation
```

1. kAFL requires a modified KVM-Nyx host kernel for efficient PT tracing and
   snapshots. The below steps build and install a custom kernel package based on
   your current/existing kernel config:

```
$ west update kvm
$ ./install.sh linux    # download, patch and build Linux
$ sudo dpkg -i linux-image*kafl+_*deb
$ sudo reboot
```

1. On reboot, make sure the new kernel is booted and KVM-NYX confirms that PT is
   supported on this CPU:

```
$ dmesg|grep KVM
 [KVM-NYX] Info:   CPU is supported!
```

1. (Optional) Lauch `kafl_fuzz.py` to verify all python dependencies are met.
   You should be able to see a help message with all the config options:

```
$ cd ~/work; pipenv shell                # activate venv
$ python3 ~/work/kafl/kafl_fuzz.py -h    # not installed version
$ kafl_fuzz.py -h                        # not installed version
```

I case of errors, you may have to hunt down some python dependencies that did
not install correctly. Try the corresponding packages provided by your
distribution and ensure that a correct path to the Qemu-Nyx binary is provided
in your local [kafl.yaml](kafl.yaml).


## Available Sample Targets

Once the above setup is done, you should try one of the available known-working
examples. The following examples are suitable as out-of-the-box test cases:

- Zephyr hello world. Follow the steps in
  [Zephyr/README](https://github.com/IntelLabs/kafl.targets/tree/master/zephyr_x86_32)

- Other (outdated) examples can be found in the [kafl.targets/ subproject](https://github.com/IntelLabs/kafl.targets/tree/master/):

  - UEFI / EDK2
  - Linux kernel and userspace targets
  - Windows + OSX targets


## Understanding Fuzzer Status

The `kafl_fuzz.py` application is not meant to execute interactively and does
not provide much output beyond basic status + errors. Instead, all status and
statistics are written directly to a `working directory` where they can be
inspected with separate tools.

 The `workdir` must be specified on startup and will usually be overwritten.
Example directory structure:

```
/path/to/workdir/
`- corpus/        - corpus of inputs, sorted by execution result
`- metadata/      - metadata associated with each input
`- stats          - overall fuzzer status
`- worker_stats_N - individual status of Worker <N>
`- serial_N.log   - serial logs for Worker <N>
`- hprintf_N.log  - guest agent logging (--log-hprintf)
`- debug.log      - debug logging (max verbosity: --log --debug)

`- traces/        - output of raw and decoded trace data (kafl_fuzz.py -trace, kafl_cov.py)
`- imports/       - staging folder for supplying new seeds at runtime
`- dump/          - staging folder to data uploads from guest to host

`- page_cache.*   - guest page cache data
`- snapshot/      - guest snapshot data
`- bitmaps/       - fuzzer bitmaps
 ...
```

The stats and metadata files are in `msgpack` format. Use the included `mcat.py`
to dump their content. A more interesting interface can be launched like this:

```
$ python3 ~/work/kafl/kafl_gui.py $workdir
```

Or use the `plot` tool to see how the corpus is evolving over time:

```
$ python3 ~/work/kafl/kafl_plot.py $workdir
$ python3 ~/work/kafl/kafl_plot.py $workdir ~/graph.dot
$ xdot ~/graph.dot
```

kAFL also records some basic stats to plot progress over time:

```
$ gnuplot -c ~/work/kafl/scripts/stats.plot $workdir/stats.csv
```

To obtain detailed coverage data, you need to collect PT traces and decode them.
Collecting binary PT traces is reasonably efficient during fuzzer runtime, using
`kafl_fuzz.py --trace`. Given an existing workdir with corpus, `kafl_cov.py` tool
will optionally re-run the corpus to collect PT traces and decode them to a list
of edges. This file can be further processed with analysis tools like Ghidra.
An example is provided for the Zephyr target:

```
$ ./targets/zephyr_x86_32/run.sh cov /dev/shm/kafl_zephyr/
$ ls /dev/shm/kafl_zephyr/traces/
```

Finally, `kafl_debug.py` contains a few more execution options such as debugging
a single payload execution with GDB attached to Qemu.


## Working with West

Check `west.yml` for customizing repository locations and revisions. Check [west
basics](https://docs.zephyrproject.org/latest/guides/west/basics.html) to learn
more. To work on one of the checked out repos, fetch the upstream git refs and
create a custom branch. To work with your own fork, change the manifest URL or
just add your fork as a remote:

```
cd ~/work/targets
git remote -v        # show remotes
git fetch github     # fetch refs
git switch -c myfork # create + switch to own branch
git remote add myrepo https://foobar.com/myrepo.git # add own repo as git remote
git push -u myrepo myfork # push your branch
```

When running `west update -k`, west will keep your branches intact or print
a message on how to restore them.


## Further Reading (need updating!)

* Step-by-step guides for [Linux](docs/linux_tutorial.md) and [Windows](docs/windows_tutorial.md)
* [Userspace fuzzing with sharedir](docs/sharedir_tutorial.md)
* [kAFL/Nyx hypercall API documentation](docs/hypercall_api.md)
* Papers and background at [nyx-fuzz.com](https://nyx-fuzz.com)

