# Fuzzing Campaign

## Running `kafl fuzz`

Everything is in place to start fuzzing our target now !

You can review the [`kafl.yaml`](https://github.com/IntelLabs/kafl.targets/blob/master/windows_x86_64/kafl.yaml) where the `qemu_image` parameter has already been configured for you.

Make sure you are running inside the [kAFL virtualenv](../../installation.md#4-setting-kafl-environment--make-env).

To start fuzzing, run the `kalf fuzz` command:

~~~shell
cd kafl/examples/windows_x86_64
(venv) $ kafl fuzz
~~~

:::{note}
You can increase the fuzzing speed by dedicating more processes to kAFL.

The default value is `1`, which means that 1 QEMU instance will be launched and fuzzed.

Depending on your target's ressources requirements and your system capabilities, you can allocate more CPUs with [`-p`](../../../reference/fuzzer_configuration.md#processes) parameter.

Example on an Intel Xeon 64 cores with 250GB of RAM, where we reach almost `90k exec/sec` in total:
````shell
(venv) $ kafl fuzz -p 32
...
(venv) $ kafl gui
...
┏━━❮❰ Activity ❱❯━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃                                                                              ┃
┃ >Worker  0:     afl_havoc │ node:    13 │ fav/lvl:     2/  1 │ exec/s:  2698 ┃
┃  Worker  1:     afl_havoc │ node:    12 │ fav/lvl:     3/  2 │ exec/s:  2838 ┃
┃  Worker  2:    afl_splice │ node:    11 │ fav/lvl:     3/  0 │ exec/s:  2817 ┃
┃  Worker  3:    afl_splice │ node:    14 │ fav/lvl:     2/  3 │ exec/s:  2762 ┃
┃  Worker  4:    afl_splice │ node:    16 │ fav/lvl:     2/  4 │ exec/s:  2763 ┃
┃  Worker  5:     afl_havoc │ node:     7 │ fav/lvl:    12/  0 │ exec/s:  2861 ┃
┃  Worker  6:    afl_splice │ node:    18 │ fav/lvl:     0/  2 │ exec/s:  2816 ┃
┃  Worker  7:     afl_havoc │ node:     3 │ fav/lvl:     2/  0 │ exec/s:  2806 ┃
┃  Worker  8:    afl_splice │ node:    11 │ fav/lvl:     3/  0 │ exec/s:  2844 ┃
┃  Worker  9:    afl_splice │ node:    14 │ fav/lvl:     2/  3 │ exec/s:  2799 ┃
┃  Worker 10:    afl_splice │ node:    14 │ fav/lvl:     2/  3 │ exec/s:  2779 ┃
┃  Worker 11:    afl_splice │ node:    11 │ fav/lvl:     3/  0 │ exec/s:  2802 ┃
┃  Worker 12:    afl_splice │ node:    12 │ fav/lvl:     3/  2 │ exec/s:  2806 ┃
┃  Worker 13:    afl_splice │ node:    13 │ fav/lvl:     2/  1 │ exec/s:  2789 ┃
┃  Worker 14:     afl_havoc │ node:     9 │ fav/lvl:     1/  1 │ exec/s:  2833 ┃
┃  Worker 15:    afl_splice │ node:    12 │ fav/lvl:     3/  2 │ exec/s:  2762 ┃
┃  Worker 16:    afl_splice │ node:    11 │ fav/lvl:     3/  0 │ exec/s:  2803 ┃
┃  Worker 17:     afl_havoc │ node:     4 │ fav/lvl:     1/  1 │ exec/s:  2818 ┃
┃  Worker 18:     afl_havoc │ node:     2 │ fav/lvl:     0/  1 │ exec/s:  2794 ┃
┃  Worker 19:    afl_splice │ node:    15 │ fav/lvl:     0/  2 │ exec/s:  2739 ┃
┃  Worker 20:    afl_splice │ node:    12 │ fav/lvl:     3/  2 │ exec/s:  2712 ┃
┃  Worker 21:     afl_havoc │ node:    14 │ fav/lvl:     2/  3 │ exec/s:  2881 ┃
┃  Worker 22:     afl_havoc │ node:    15 │ fav/lvl:     0/  2 │ exec/s:  2863 ┃
┃  Worker 23:    afl_splice │ node:    13 │ fav/lvl:     2/  1 │ exec/s:  2794 ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
````
:::

The fuzzer will boot the QEMU Windows image, and the `vuln_test.exe` program should start its execution a few minutes afterwards, when the boot sequence reaches userspace.

When the [`hprintf`](../../../reference/hypercall_api.md#hprintf) messages start to be displayed on stdout, you know that `vuln_test.exe` is executing successfuly and we are reaching the harness soon.

```{code-block}
---
caption: kAFL Fuzzer execution
---
<< kAFL Fuzzer >>

Warning: Launching without --seed-dir?
No PT trace region defined.
00:00:00:     0 exec/s,    0 edges,  0% favs pending, findings: <0, 0, 0>
Worker-00 Launching virtual machine...
/home/mtarral/kafl/kafl/qemu/x86_64-softmmu/qemu-system-x86_64
        -enable-kvm
        -machine kAFL64-v1
        -cpu kAFL64-Hypervisor-v1,+vmx
        -no-reboot
        -net none
        -display none
        -chardev socket,server,id=nyx_socket,path=/dev/shm/kafl_mtarral/interface_0
        -device nyx,chardev=nyx_socket,workdir=/dev/shm/kafl_mtarral,worker_id=0,bitmap_size=65536,input_buffer_size=131072
        -device isa-serial,chardev=kafl_serial
        -chardev file,id=kafl_serial,mux=on,path=/dev/shm/kafl_mtarral/serial_00.log
        -m 4096
        -drive file=/home/mtarral/.local/share/libvirt/images/windows_x86_64_vagrant-kafl-windows.img
        -monitor unix:/tmp/monitor.sock,server,nowait
        -fast_vm_reload path=/dev/shm/kafl_mtarral/snapshot/,load=off
[QEMU-NYX] Max Dirty Ring Size -> 1048576 (Entries: 65536)
qemu-system-x86_64: warning: host doesn't support requested feature: CPUID.07H:EBX.hle [bit 4]
qemu-system-x86_64: warning: host doesn't support requested feature: CPUID.07H:EBX.rtm [bit 11]
[QEMU-NYX] Dirty ring mmap region located at 0x7f3065101000
[QEMU-NYX] Warning: Invalid sharedir...
[QEMU-NYX] Booting VM to start fuzzing...
Initiate fuzzer handshake...
        host_config.bitmap_size: 0x10000
        host_config.ijon_bitmap_size: 0x1000
        host_config.payload_buffer_size: 0x20000
Submitting bug check handlers
Worker-00 Entering fuzz loop..
00:00:47: Got    1 from    0: exit=R, 11/ 0 bits, 11 favs, 0.85msec, 0.2KB (kickstart)
```

:::{Note}
For the full command-line reference, please refer to [Fuzzer Configuration](../../../reference/fuzzer_configuration.md) page.
:::

## Follow the progress with `kafl gui`

```{include} ../../gui.md
```

You should see kAFL reporting `2` crashes after 10-20 minutes (depending on your ressources allocation)

```{code-block} shell
---
caption: kAFL GUI crash founds
---
┏━━❮❰ Progress ❱❯━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃                                                                              ┃
┃ Paths:            │ Bitmap:           │ Findings:                            ┃
┃  Total:        11 │                   │  Crash:           2 (N/A)     18m51s ┃
┃  Seeds:         4 │  Edges:        30 │  AddSan:          0 (N/A)   None Yet ┃
┃  Favs:         10 │  Blocks:       61 │  Timeout:         5 (N/A)     19m38s ┃
┃  Norm:          1 │  p(col):     0.0% │  Regular:        11 (N/A)     18m54s ┃
┠──────────────────────────────────────────────────────────────────────────────┨
```

Once you have found at least one crash, you can stop fuzzing and jump onto the next step !
