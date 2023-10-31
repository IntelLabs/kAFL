# 4 - Fuzzing campaign

## Running `kafl fuzz`

With all configurations and dependencies set, you're ready to commence the fuzzing campaign.

You can review the [`kafl.yaml`](https://github.com/IntelLabs/kafl.targets/blob/master/linux-user/dvkm/kafl.yaml) config file, where the `sharedir`, `qemu_kernel`, `qemu_initrd` and `qemu_append` parameters have already been configured:

:::{code-block} yaml
# exposing host files through "sharedir" interface
sharedir: '@format {env[PWD]}/sharedir'

# additional kAFL configuration
qemu_kernel: '@format {env[EXAMPLES_ROOT]}/linux-user/linux_kafl_agent/arch/x86/boot/bzImage'
qemu_initrd: '@format {env[EXAMPLES_ROOT]}/linux-user/scripts/kafl_initrd.cpio.gz'

# use hprintf=7 for full printk verbosity
qemu_append: root=/dev/vda1 rw nokaslr oops=panic nopti mitigations=off console=ttyS0 earlyprintk=serial,ttyS0 ignore_loglevel
:::

Ensure you are running inside the [kAFL virtualenv](../../installation.md#4-setting-kafl-environment--make-env).

To start fuzzing, run the following `kafl fuzz` command:

~~~shell
cd kafl/examples/linux-user/dvkm
(venv) $ kafl fuzz --purge --log-crashes
~~~

- [`--purge`](../../../reference/fuzzer_configuration.md#purge): removes the `$KAFL_WORKDIR` directory if it already exists before starting the new campaign.
- [`--log-crashes`](../../../reference/fuzzer_configuration.md#log_crashes): redirect hprintf log message to a log file, and to `$KAFL_WORKDIR/logs/` for any new found crashing or timeout payload.

:::{note}
You can increase the fuzzing speed by dedicating more processes to kAFL.

The default value is `1`, which means that 1 QEMU instance will be launched and fuzzed.

Depending on your target's ressources requirements and your system capabilities, you can allocate more CPUs with [`-p`](../../../reference/fuzzer_configuration.md#processes) parameter.
:::

```{code-block}
---
caption: kAFL Fuzzer execution
---

```

:::{Note}
For the full command-line reference, please refer to [Fuzzer Configuration](../../../reference/fuzzer_configuration.md) page.
:::

## Follow the progress with `kafl gui`

```{include} ../../gui.md
```

After a few minutes (depending on your system and resource allocation), you should start to see kAFL reporting crashes:

```{code-block} shell
---
caption: kAFL GUI crash founds
---
┏━━❮❰ Progress ❱❯━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃                                                                              ┃
┃ Paths:            │ Bitmap:           │ Findings:                            ┃
┃  Total:        38 │                   │  Crash:           3 (N/A)     2m00s  ┃
┃  Seeds:        22 │  Edges:       100 │  AddSan:          0 (N/A)   None Yet ┃
┃  Favs:         38 │  Blocks:      149 │  Timeout:        18 (N/A)        28s ┃
┃  Norm:          1 │  p(col):     0.2% │  Regular:        38 (N/A)      1m27s ┃
┠──────────────────────────────────────────────────────────────────────────────┨
```

Once you've observed at least one crash, you can terminate the fuzzing process using `CTRL-C` and proceed to the next step of the analysis.
