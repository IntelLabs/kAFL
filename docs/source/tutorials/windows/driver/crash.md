# Crash Analysis

## Exploring the corpus

Let's start by locating the payloads associated with these crashes.
We need to go to the `KAFL_WORKDIR`, into the crash reports

```{code-block} shell
---
caption: Displaying payload crash files from the corpus
---
(venv) $ pushd $KAFL_WORKDIR
(venv) /dev/shm/kafl_mtarral$ ls -l corpus/crash/
total 8
-rw-r--r-- 1 mtarral mtarral 14 Sep 11 05:54 payload_00015
-rw-r--r-- 1 mtarral mtarral 26 Sep 11 05:54 payload_00018
```

The payload filename contains the payload ID: `00015` and `00018` here.

We can view the hexdump representation of the payloads to highlight their contents:
```{code-block} shell
---
caption: Payloads hexdump representation
---
(venv) /dev/shm/kafl_mtarral$ find corpus/crash -type f -exec hexdump -C {} \;
00000000  50 77 6e 54 6f 77 6e 54  6f 97 c5 00 00 10 15 ab  |PwnTownTo.......|
00000010  b9 97 c5 00 00 10 15 ab  b9 1e                    |..........|
0000001a
00000000  77 30 30 74 77 69 97 bc  38 58 e4 c0 b9 1e        |w00twi..8X....|
0000000e
```

We can clearly identify the 2 strings that we found earlier during the [code analysis](target.md#vulnerability) analysis.
- `PwnTown`
- `w00t`

## Locating the vulnerability

Now that we have crashing payloads in our corpus, the next step is to locate where the code actually crashes.

### Windows crash dumps

The best way is to rely on Windows own crash reporting system.

When a crash occurs, Windows dumps contextual information into a `minidump` file (usually under `%SystemRoot%\Minidump` folder.)

By extracting these files from the guest, and analyzing them with `WinDBG`, you will be able to reveal the precise location of the crash, and the corresponding faulty line.

### Adding debug logs

Another possibility would be to add debug statements and running multiple campaigns to nail down the crash location.

:::{Warning}
At the time of this writing, kAFL hypercalls are not compatible with MSVC compiler.

Therefore adding `hprintf()` log statement in the driver is not a possibility.
::::{Note}
Exploring the case where you can use `hprintf()` statements, it should be coupled with [`--log-crashes`](../../../reference/fuzzer_configuration.md#log_crashes)
to get per crash log files.
::::

We need to rely here on Windows own debugging facility named [DbgPrint()](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-dbgprint).
:::
