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

| Keys              |
| ----------------- |
| `work_dir`        |
| `purge`           |
| `resume`          |
| `processes`       |
| `verbose`         |
| `quiet`           |
| `log`             |
| `debug`           |
| `seed_dir`        |
| `dict`            |
| `funky`           |
| `afl_dump_mode`   |
| `afl_skip_zero`   |
| `afl_arith_max`   |
| `radamsa`         |
| `redqueen`        |
| `redqueen_hashes` |
| `redqueen_hammer` |
| `redqeen_simple`  |
| `cpu_offset`      |
| `abort_time`      |
| `abort_exec`      |
| `timeout_soft`    |
| `timeout_check`   |
| `kickstart`       |
| `radamsa_path`    |
| `qemu_image`      |
| `qemu_snapshot`   |
| `qemu_bios`       |
| `qemu_kernel`     |
| `qemu_initrd`     |
| `qemu_append`     |
| `qemu_memory`     |
| `qemu_base`       |
| `qemu_serial`     |
| `qemu_extra`      |
| `qemu_path`       |
| `ip0`             |
| `ip1`             |
| `ip2`             |
| `ip3`             |
| `sharedir`        |
| `reload`          |
| `snapshot_reload` |
| `gdbserver`       |
| `log_hprintf`     |
| `log_crashes`     |
| `timeout_hard`    |
| `payload_size`    |
| `bitmap_size`     |
| `trace`           |
| `trace_cb`        |
| `input`           |
| `iterations`      |
| `action`          |
| `ptdump_path`     |

Note: Configuration keys are case insensitive:
~~~YAML
qemu_memory: 256
# and
QEMU_MEMORY: 256
~~~

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
