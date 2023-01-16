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

:::{note}
Default: `0`

Command-line: `--abort-exec`
:::

### `abort_time`

:::{note}
Default: `0`

Command-line: `--abort-time`
:::

### `action`

kAFL subcommand to execute.

:::{note}
Default: `fuzz`

Command-line: `kafl <action>`. Choices available: `fuzz`, `cov`, `gui`, `mcat`, `plot`
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

:::{note}
Default: `false`

Command-line: `--debug`
:::

### `dict`

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

:::{note}
Default: `false`

Command-line: `--gdbserver`
:::

### `input`

:::{note}
Default: `None`

Command-line: `--input`
:::

### `ip0-1-2-3`

:::{note}
Default: `None`

Command-line: `--ip0`, `ip1`, `ip2`, `ip3`
:::

### `iterations`

:::{note}
Default: `5`

Command-line: `--iterations`
:::

### `kickstart`

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

:::{note}
Default: `false`

Command-line: `--log`
:::

### `payload_size`

:::{note}
Default: `131072`

Command-line: `--payload-size`
:::

### `processes`

:::{note}
Default: `1`

Command-line: `--processes`
:::

### `ptdump_path`

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

:::{note}
Default: `nokaslr oops=panic nopti mitigations=off console=ttyS0`

Command-line: `--qemu-append`
:::

### `qemu_base`

:::{note}
Default: `-enable-kvm -machine kAFL64-v1 -cpu kAFL64-Hypervisor-v1,+vmx -no-reboot -net none -display none`

Command-line: `--qemu-base`
:::

### `qemu_bios`

:::{note}
Default: `None`

Command-line: `--bios`
:::

### `qemu_extra`

:::{note}
Default: `None`

Command-line: `--qemu-extra`
:::

### `qemu_image`

:::{note}
Default: `None`

Command-line: `--image`
:::

### `qemu_initrd`

:::{note}
Default: `None`

Command-line: `--initrd`
:::

### `qemu_kernel`

:::{note}
Default: `None`

Command-line: `--kernel`
:::

### `qemu_memory`

:::{note}
Default: `256`

Command-line: `--memory`
:::

### `qemu_path`

:::{note}
Default: `$QEMU_ROOT/x86_64-softmmu/qemu-system-x86_64`

Command-line: `--qemu-path`
:::

### `qemu_serial`

:::{note}
Default: `-device isa-serial,chardev=kafl_serial`

Command-line: `--qemu-serial`
:::

### `qemu_snapshot`

:::{note}
Default: `None`

Command-line: `--snapshot`
:::

### `quiet`

:::{note}
Default: `false`

Command-line: `--quiet`
:::

### `radamsa_path`

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

:::{note}
Default: `None`

Command-line: `--seed-dir`
:::

### `sharedir`

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

:::{note}
Default: `false`

Command-line: `--trace-cb`
:::

### `trace`

:::{note}
Default: `false`

Command-line: `--trace`
:::

### `verbose`

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
