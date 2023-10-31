# Fuzzer Configuration

The kAFL fuzzer configuration can be changed via config files, environment variables and command line switches.

The [Dynaconf](https://www.dynaconf.com/) framework is used behind the scenes for configuration management, so
everything that you learn from Dynaconf's documentation should also be applicable for kAFL fuzzer.

## Configuration sources and precedence

All configuration files are using the `YAML` format.

1. kAFL fuzzer packaged default configuration file: [`kafl_fuzzer/common/config/default_settings.yaml`](https://github.com/IntelLabs/kafl.fuzzer/blob/master/kafl_fuzzer/common/config/default_settings.yaml)
2. System-level config file: `/etc/xdg/kAFL/settings.yaml`
3. User-level config file: `$HOME/.config/kAFL/settings.yaml`
4. Local config file: `$PWD/kafl.yaml`
5. Environment variable `KAFL_CONFIG_FILE` if specified
6. Command line arguments. Ex: `--work_dir /dev/shm/kafl_test_feature`
7. Configuration keys specified by environment variables prefixed by `KAFL_`. Ex: `KAFL_PROCESSES=8`

Note: if `KAFL_CONFIG_FILE` is specified but points to a non-existing file, a validation error will be raised (to warn the user).

## Overriding settings from environment variables

You can override any setting key by exporting an environment variable prefixed by `KAFL_`.

Example

~~~shell
export KAFL_QEMU_MEMORY=1024
export KAFL_LOG_HRPINTF=TRUE
~~~


## Configuration keys

The following section lists all configuration keys avaialble in kAFL, and their corresponding command line switches, if any.

:::{note}
Configuration keys are case insensitive:
~~~YAML
qemu_memory: 256
# and
QEMU_MEMORY: 256
~~~
:::

### `abort_exec`

Exit kAFL fuzzing a after `<n>` total executions.

:::{note}
Default: `0`

Command-line: `--abort-exec`
:::

### `abort_time`

Builtin timeout to stop kafl fuzzing after `<n>` seconds elapsed.

:::{note}
Default: `0`

Command-line: `--abort-time`
:::

### `action`

kAFL debug action.

Choices available:

| Action          | Description                                              |
| --------------- | -------------------------------------------------------- |
| `benchmark`     | Perform performance benchmark                            |
| `gdb`           | Run payload with GDB server (must compile with redqueen) |
| `trace`         | Peform trace run                                         |
| `trace-qemu`    | Perform trace run and print QEMU stdout                  |
| `noise`         | Perform run and measure non determinism                  |
| `printk`        | redirect printk calls to kAFL                            |
| `redqueen`      | Run redqueen debugger                                    |
| `redqueen-qemu` | Run redqueen debugger and print QEMU stdout              |
| `verify`        | Run verification steps                                   |

:::{note}
Command-line: `--action`.
:::

### `afl_arith_max`

Maximum number of increment/decrement steps in AFL-style arithmetic mutation
(only affects deterministic stage, not havoc).

:::{note}
Default: 34

Command-line: `--afl-arith-max`
:::

### `afl_dumb_mode`

Skip AFL-style deterministic stages (`bitflip`, `arithmetic`, `interesting` mutations).

:::{note}
Default: `false`

Command-line: `--afl-dumb-mode`, `-D`
:::

### `afl_skip_zero`

Skip mutating zero-bytes in AFL-style deterministic stages.

:::{note}
Default: `false`

Command-line: `--afl-skip-zero`
:::

### `bitmap_size`

Size of feedback bitmap (must be power of 2).

:::{note}
Default: `65536`

Command-line: `--bitmap-size`
:::

### `cpu_offset`

Modify automated CPU pinning to start at vCPU `n` and assign Qemu/Worker
instances to the next [`-p`](#processes) vCPUs.

:::{note}
Default: `0`

Command-line: `--cpu-offset <n>`
:::

### `debug`

Enable additional (expensive) debug messages during execution.

- switches logging to `DEBUG` level
- toggles QEMU `nyx` log item (`-d nyx`), only effective if [`--log`](#log) has been specified
- stores funky input data in `$WORKDIR/funky`. See [`--funky`](#funky) and [workdir reference](./workdir_layout.md)

Implies [`--verbose`](#verbose).

:::{note}
Default: `false`

Command-line: `--debug`
:::

### `dict`

Use file `<path>` as source of dictionary inputs in havoc stage.

:::{note}
Default: `None`

Command-line: `--dict <path>`
:::

### `funky`

::::{tab-set}
:::{tab-item} kafl fuzz

Validate new (non-crashing/non-timeout) inputs multiple times and add to corpus
if consistent new coverage is found on majority of re-runs.  Executes payloads
8 times by default and accepts payloads that reproduce with 75% probability. In
combination with `--debug`, non-reproducible inputs are stored in
`$KAFL_WORKDIR/funky/`. Useful with non-deterministic targets.

:::
:::{tab-item} kafl cov
Output any additional found coverage and payloads in combination with `--trace --action noise`.
:::
::::

:::{note}
Default: `false`

Command-line: `--funky`
:::

### `gdbserver`

Starts QEMU GDB server (Extends QEMU command line with `-s -S`).

From QEMU command line help:
- `-s`: shorthand for -gdb tcp::1234
- `-S`: freeze CPU at startup (use 'c' to start execution)

:::{note}
Default: `false`

Command-line: `--gdbserver`
:::

### `grimoire`

Enable the [Grimoire](https://github.com/RUB-SysSec/grimoire) fuzzer stage.

:::{note}
Default: `false`

Command-line: `--grimoire`
:::


### `input`

::::{tab-set}
:::{tab-item} kafl cov
Sets the kAFL workdir to be processed for coverage information. Will
automatically process files in `corpus/{crash,kasan,regular}/` (but not `timeout`).
:::
:::{tab-item} kafl debug
Sets the payload file to be used as input for the debugging session.
:::
::::

:::{note}
Default: [workdir](#work_dir) value

Command-line: `--input <path>`
:::

### `ip0-1-2-3`

Set the IP filter ranges (code ranges) to be used with Intel PT. The filter
ranges may also be set by the agent using the (`RANGE_SUBMIT` hypercall)[hypercall_api.md].

Not setting a IP filter region is currently not supported.

:::{note}
Default: `None`

Command-line: `--ip0`, `--ip1`, `--ip2`, `--ip3`
:::

### `iterations`

Execute the debugged payload `<n>` times.

Used by `noise`, `trace` and `trace-qemu` debug [actions](#action) in case of
non-deterministic execution.

:::{note}
Default: `5`

Command-line: `--iterations`

Applicable subcommands: `debug`
:::

### `kickstart`

When no payloads in queue or more workers than available corpus payloads,
let the worker kickstart fuzzing with random strings of length `n`.
Useful to test a new harness that has no well defined seeds.

Enabled by default. Set `0` to disable.

:::{note}
Default: `256`

Command-line: `--kickstart <n>`
:::

### `log`

Add an additional file logging handler to `$KAFL_WORKDIR/kafl_fuzzer.log`.
Also redirects Qemu log output to `$KAFL_WORKDIR/qemu_trace_NN.log`, if any.

:::{note}
Default: `false`

Command-line: `--log`
:::

### `log_crashes`

Like `log_hprintf`, but copy the hprintf log to `$KAFL_WORKDIR/logs/` for any
new found `{crash,kasan,timeout}` type payload.  Also truncates the main hprintf
log after every execution.

This is the recommended guest logging option to collect live guest logs
corresponding to new found non-regular payloads, while avoiding OOM due to huge
hprintf logs.

:::{note}
Default: `false`

Command-line: `--log-crashes`
:::

### `log_hprintf`

Redirect guest `hprintf` output to `$KAFL_WORKDIR/hprintf_NN.log` (see [PRINTF hypercall](hypercall_api.md)).

Creates a linear log of Guest execution across snapshot/restore. Recommended for
debugging guest/harness execution.

:::{note}
Default: `false`

Command-line: `--log-hprintf`
:::

### `payload_size`

Maximum payload size in bytes. Must be multiple of page size (4096 bytes).

:::{note}
Default: `131072`

Command-line: `--payload-size <n>`
:::

### `processes`

Number of processes to launch for parallelized fuzzing and coverage.

:::{note}
Default: `1`

Command-line: `--processes <n>`
:::

### `ptdump_path`

Path to ptdump executable.

:::{note}
Default: `$LIBXDC_ROOT/build/ptdump_static`

Command-line: `--ptdump-path`
:::

### `purge`

Purge the [KAFL workdir](#work_dir) directory at startup.

:::{note}
Default: `false`

Command-line: `--purge`
:::

### `qemu_append`

Kernel command line if [`--kernel`](#qemu_kernel) is used.

Corresponds to QEMU `-append <cmdline>` argument.

:::{note}
Default: `nokaslr oops=panic nopti mitigations=off console=ttyS0`

Command-line: `--qemu-append`
:::

### `qemu_base`

Baseline for QEMU command-line.

:::{note}
Default: `-enable-kvm -machine kAFL64-v1 -cpu kAFL64-Hypervisor-v1,+vmx -no-reboot -net none -display none`

Command-line: `--qemu-base`
:::

### `qemu_bios`

Set custom BIOS image to be used by QEMU.

Corresponds to QEMU `-bios <file>` argument.

:::{note}
Default: `None`

Command-line: `--bios`
:::

### `qemu_extra`

Extra string appended to QEMU command line. Useful to override specific Qemu flags.

:::{note}
Default: `None`

Command-line: `--qemu-extra`
:::

### `qemu_image`

Path to Qemu disk image.

Corresponds to QEMU `-drive file=<disk>` argument.

:::{note}
Default: `None`

Command-line: `--image`
:::

### `qemu_initrd`

Initial ram disk for QEMU.

Corresponds to QEMU `-initrd <file>` argument.

:::{note}
Default: `None`

Command-line: `--initrd`
:::

### `qemu_kernel`

bzImage to use as kernel image for QEMU.

Corresponds to QEMU `-kernel <image>` argument.

:::{note}
Default: `None`

Command-line: `--kernel`
:::

### `qemu_memory`

Amount of memory in `MB` for QEMU.

Corresponds to QEMU `-m <size>` argument.

:::{note}
Default: `256`

Command-line: `--memory <n>`, `-m <n>`
:::

### `qemu_path`

Path to QEMU executable with Nyx patches.

:::{note}
Default: `$QEMU_ROOT/x86_64-softmmu/qemu-system-x86_64`

Command-line: `--qemu-path <path>`
:::

### `qemu_serial`

Extend QEMU command line with the configuration value, and then append
`-chardev file,id=kafl_serial,mux=on,path=$KAFL_WORKDIR/serial_<qemu_pid>.log`.

:::{note}
Default: `-device isa-serial,chardev=kafl_serial`

Command-line: `--qemu-serial`
:::

### `qemu_snapshot`

Path to VM pre-snapshot directory. Use with manual `pre-snapshot` creation (`LOCK` hypercall)[hypercall_api.md]

:::{note}
Default: `None`

Command-line: `--snapshot <path>`
:::

### `quiet`

Set Python [`logging`](https://docs.python.org/3/library/logging.html) level to [`WARNING`](https://docs.python.org/3/library/logging.html#logging-levels).

:::{note}
Default: `false`

Command-line: `--quiet`
:::

### `radamsa_path`

Path to radamsa executable.

:::{note}
Default: `$RADAMSA_ROOT/bin/radamsa`

Command-line: `--radamsa-path <path>`
:::

### `radamsa`

Enable radamsa mutation as part of `havoc` stage.

:::{note}
Default: `false`

Command-line: `--radamsa`
:::

### `redqueen_simple`

Modify redqueen to also process 'simple' inputs that would likely be found by
subsequent deterministic/havoc mutations.

:::{note}
Default: `false`

Command-line: `--redqueen-simple`
:::

### `redqueen_hammer`

Enable Redqueen jump table hammering.

:::{note}
Default: `false`

Command-line: `--redqueen-hammer`
:::

### `redqueen_hashes`

Enable Redqueen checksum fixer (broken).

:::{note}
Default: `false`

Command-line: `--redqueen-hashes`
:::

### `redqueen`

Enable Redqueen analysis + mutation stages.

:::{note}
Default: `false`

Command-line: `--redqueen`
:::

### `reload`

Reload the snapshot only on non-regular executions or every `<N>` regular executions.
Set to `0` for fully persistent mode execution.
Set to '>1' for partial persistent mode execution.

For targets that support persistent mode, setting '--reload' somewhere in the
range of 10-100 tends to yield good performance/stability trade-off.

:::{note}
Default: `1`

Command-line: `--reload <n>`, `-R <n>`
:::

### `resume`

Tell kAFL to resume operation based on an existing workdir. This is currently
limited to `kafl cov` and `kafl debug`, where it will cause the Qemu instance to
initialize based on existing Nyx `snapshot/` and `page_cache.*` files.

Resuming a complete fuzzer campaign (kafl fuzz) is not yet supported.

:::{note}
Default: `false`

Command-line: `--resume`
:::

### `seed_dir`

Specify a directory `<path>` to use as seed directory. The directory is
traversed recursively and files are copied to the kAFL
[workdir](../reference/workdir_layout.md) as `$KAFL_WORKDIR/imports/seed_xxx`,
where there are consumed upon fuzzer startup.

:::{note}
Default: `None`

Command-line: `--seed-dir <path>`
:::

### `sharedir`

Path to the Qemu 'sharedir' directory. Files in this folder will be made
available for the agent to download via (`REQ_STREAM_DATA` hypercall)[hypercall_api.md].

Appends `,sharedir=<value>` to the `nyx` QEMU device.

:::{note}
Default: `None`

Command-line: `--sharedir <path>`
:::

### `timeout_check`

When using both `timeout_hard` and `timeout_soft`, check that a payload reported as
'timeout' also produces a timeout when executing with maximum timeout 'timeout_hard'.

:::{note}
Default: `false`

Command-line: `--t-check`
:::

### `timeout_hard`

Hard execution timeout (seconds)

:::{note}
Default: `4`

Command-line: `--t-hard`
:::

### `timeout_soft`

Soft execution timeout (seconds). Used as initial lower timeout for Qemu
instances and then adapted based on seen performance, up to the maximum of
`timeout_hard`.

:::{note}
Default: `0.001`

Command-line: `--t-soft`
:::

### `trace_cb`

Run Qemu in 'callback-trace' mode, where PT traces are directly decoded using
a libxdc callback function. This tends to significantly slow down execution and
results in different coverage bitmaps. Deprecated.

Appends `,edge_cb_trace` to the `nyx` QEMU device.

:::{note}
Default: `false`

Command-line: `--trace-cb`
:::

### `trace`

Run Qemu in `dump-trace` mode, where binary PT traces are directly stored to
the workdir by each Qemu process. For any new discovered payloads, kAFL stores
the corresponding binary traces to `$KAFL_WORKDIR/traces/` for later decoding
with `kafl cov`.
This is the recommeded trace mode as it incurrs minimal slow-down and also
works for non-deterministic targets.

Appends `,dump_pt_trace` to the `nyx` QEMU device.

:::{note}
Default: `false`

Command-line: `--trace`
:::

### `verbose`

Enable verbose output by setting Python [`logging`](https://docs.python.org/3/library/logging.html) level to [`DEBUG`](https://docs.python.org/3/library/logging.html#logging-levels).

This option is also useful to dump and debug kafl configuration at load-time.

Example with [Fuzzing the Linux kernel](../tutorials/linux/fuzzing_linux_kernel.md) tutorial, if `--verbose` switch were to be added to the command line:

First kAFL will dump the list of loaded configuration files.
Check the [load order](#configuration-sources-and-precedence)
~~~
Loaded configuration files:
['/home/mtarral/kAFL/kafl/fuzzer/kafl_fuzzer/common/config/default_settings.yaml',
 '/home/mtarral/kAFL/kafl/examples/linux-kernel/./kafl_config.yaml']
~~~

Then the command-line configuration as parser by [argparse](https://docs.python.org/3/library/argparse.html)
~~~
Command line configuration:
{'abort_exec': None,
 'abort_time': None,
 'afl_arith_max': None,
 'afl_dumb_mode': True,
...
~~~

Followed by the configuration values extracted from the loaded config files:
~~~
Loaded configuration values:
{'env_global': {'CONFIG_FILE': './kafl_config.yaml',
                'ROOT': '/home/mtarral/kAFL/kafl',
                'WORKDIR': '/dev/shm/kafl_mtarral',
                'WORKSPACE': '/home/mtarral/kAFL'},
 'yaml': {'AFL_ARITH_MAX': 34,
          'BITMAP_SIZE': 65536,
          'CPU_OFFSET': 0,
          'DEBUG': False,
...
~~~

As the command line supersedes the configuration files, kAFL will override these values and finally dump the definitive configuration:
~~~
Final configuration:
{'ABORT_EXEC': 0,
 'ABORT_TIME': 0.0,
 'AFL_ARITH_MAX': 34,
 'AFL_DUMB_MODE': True,
~~~

:::{note}
Default: `false`

Command-line: `--verbose`
:::

### `work_dir`

The workdir is used by kAFL to accumulate results and communicate with QEMU and other processes.
It is the primary location for inspecting the status of a previous or still running kAFL session.

Also, any post-processing steps such as triage or coverage analysis typically builds up on an existing workdir.

:::{note}
Default: `/dev/shm/kafl_$USER`

Command-line: `--workdir`
:::

:::{seealso}
See also the [Workdir Layout](./workdir_layout.md) reference.
:::
