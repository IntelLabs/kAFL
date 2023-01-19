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

:::{note}
Default: `false`

Command-line: `--afl-arith-max`
:::

### `afl_dumb_mode`

:::{note}
Default: `false`

Command-line: `--afl-dumb-mode`
:::

### `afl_skip_zero`

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

:::{note}
Default: `0`

Command-line: `--cpu-offset`
:::

### `debug`

Enable verbose output by setting Python [`logging`](https://docs.python.org/3/library/logging.html) level to [`DEBUG`](https://docs.python.org/3/library/logging.html#logging-levels).

Identical to [`verbose`](#verbose).

:::{note}
Default: `false`

Command-line: `--debug`
:::

### `dict`

File `<path>` of strings as inputs for [Grimoire](https://github.com/RUB-SysSec/grimoire).

:::{note}
Default: `None`

Command-line: `--dict`
:::

### `funky`

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

### `input`

::::{tab-set}
:::{tab-item} kafl cov
Sets the input data directory for the coverage analysis.
:::
:::{tab-item} kafl debug
Sets the payload file to be used as input for the debugging session.
:::
::::

:::{note}
Default: `None`

Command-line: `--input`
:::

### `ip0-1-2-3`

IP ranges to be used as filter inputs for Intel PT.

If `ip0` is not set, PT tracing will be disabled and kAFL will turn into a blind fuzzer.

:::{note}
Default: `None`

Command-line: `--ip0`, `--ip1`, `--ip2`, `--ip3`
:::

### `iterations`

Execute the debugged payload `<n>` times.

Used by `noise`, `trace` and `trace-qemu` debug [actions](#action).

:::{note}
Default: `5`

Command-line: `--iterations`

Applicable subcommands: `debug`
:::

### `kickstart`

Kickstart fuzzing with `<n>` byte random strings.

Set `0` to disable.

:::{note}
Default: `256`

Command-line: `--kickstart`
:::

### `log_crashes`

:::{note}
Default: `false`

Command-line: `--log-crashes`
:::

### `log_hprintf`

:::{note}
Default: `false`

Command-line: `--log-hprintf`
:::

### `log`

Add an additional file logging handler to `$KAFL_WORKDIR/kafl_fuzzer.log`.

:::{note}
Default: `false`

Command-line: `--log`
:::

### `payload_size`

Maximum payload size in bytes (minus headers)

:::{note}
Default: `131072`

Command-line: `--payload-size`
:::

### `processes`

Number of processes to launch for parallelized fuzzing and coverage.

:::{note}
Default: `1`

Command-line: `--processes`
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

BIOS to be used by QEMU.

Corresponds to QEMU `-bios <file>` argument.

:::{note}
Default: `None`

Command-line: `--bios`
:::

### `qemu_extra`

Additional arguments for QEMU command line.

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

Command-line: `--memory`
:::

### `qemu_path`

Path to QEMU executable with Nyx patches.

:::{note}
Default: `$QEMU_ROOT/x86_64-softmmu/qemu-system-x86_64`

Command-line: `--qemu-path`
:::

### `qemu_serial`

Extend QEMU command line with the configuration value, and then append `-chardev file,id=kafl_serial,mux=on,path=$KAFL_WORKDIR/serial_<qemu_pid>.log`.

:::{note}
Default: `-device isa-serial,chardev=kafl_serial`

Command-line: `--qemu-serial`
:::

### `qemu_snapshot`

Path to VM pre-snapshot directory.

:::{note}
Default: `None`

Command-line: `--snapshot`
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

Command-line: `--radamsa-path`
:::

### `radamsa`

:::{note}
Default: `false`

Command-line: `--radamsa`
:::

### `redqeen_simple`

:::{note}
Default: `false`

Command-line: `--redqueen-simple`
:::

### `redqueen_hammer`

:::{note}
Default: `false`

Command-line: `--redqueen-hammer`
:::

### `redqueen_hashes`

:::{note}
Default: `false`

Command-line: `--redqueen-hashes`
:::

### `redqueen`

:::{note}
Default: `false`

Command-line: `--redqueen`
:::

### `reload`

Reload the snapshot every `<N>` execs.

Increasing this number will boost the fuzzer's speed, however it will allow multiple payloads to be executed in a potentially "uncleaned" VM state.

:::{note}
Default: `1`

Command-line: `--reload`
:::

### `resume`

:::{note}
Default: `false`

Command-line: `--resume`
:::

### `seed_dir`

Specify a directory `<path>` from which any file (at any depth) will be used as imported seed in the kAFL [workdir](../reference/workdir_layout.md) as `$KAFL_WORKDIR/imports/seed_xxx`.

:::{note}
Default: `None`

Command-line: `--seed-dir`
:::

### `sharedir`

Path to the page buffer share directory.

Appends `,sharedir=<value>` to the `nyx` QEMU device.

:::{note}
Default: `None`

Command-line: `--sharedir`
:::

### `timeout_check`

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

:::{note}
Default: `0.001`

Command-line: `--t-soft`
:::

### `trace_cb`

Store decoded PT traces of new inputs.

Appends `,dump_pt_trace` to the `nyx` QEMU device.

:::{note}
Default: `false`

Command-line: `--trace-cb`
:::

### `trace`

Store binary PT traces of new inputs (fast).

Appends `,edge_cb_trace` to the `nyx` QEMU device.

:::{note}
Default: `false`

Command-line: `--trace`
:::

### `verbose`

Enable verbose output by setting Python [`logging`](https://docs.python.org/3/library/logging.html) level to [`DEBUG`](https://docs.python.org/3/library/logging.html#logging-levels).

This option is also useful to dump and debug kafl configuration at load-time.

Example with [Fuzzing the Linux kernel](../tutorials/fuzzing_linux_kernel.md) tutorial, if `--verbose` switch were to be added to the command line:

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



## Overriding settings from environment variables

You can override any setting key by exporting an environment variable prefixed by `KAFL_`.

Example

~~~shell
export KAFL_QEMU_MEMORY=1024
export KAFL_LOG_HRPINTF=TRUE
~~~

## Dynaconf CLI

[Dynaconf](https://www.dynaconf.com/) comes with a [CLI](https://www.dynaconf.com/cli/) tool that can be used to interact with the project configuration.

To list the default settings:

~~~shell
dynaconf -i kafl_fuzzer.common.config.settings list
~~~
