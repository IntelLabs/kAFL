# 5 - Exploring campaign results

Upon completing a brief fuzzing campaign, you should have observed several crashes. This section will guide you through the analysis of these crashes.

## Exploring the corpus

First, navigate to the directory where kAFL stores crash reports, located within `$KAFL_WORKDIR` at `📂 corpus/crash`.

This directory will contain payload files, each named with a unique identifier, such as `payload_00030`.

```{code-block} shell
---
caption: Displaying payload crash files from the corpus
---
(.venv) $ pushd $KAFL_WORKDIR
(.venv) mtarral@b49691bd4b34:/dev/shm/kafl_mtarral$ ls -l corpus/crash/
total 16
-rw-r--r-- 1 mtarral mtarral 12 Oct 25 16:21 payload_00030
-rw-r--r-- 1 mtarral mtarral 12 Oct 25 16:21 payload_00031
-rw-r--r-- 1 mtarral mtarral 12 Oct 25 16:21 payload_00033
-rw-r--r-- 1 mtarral mtarral  7 Oct 25 16:22 payload_00060
```

To gain further insights into these payloads, let's examine their hexdump representation.

```{code-block} shell
---
caption: Hexdump representation
---
(.venv) mtarral@b49691bd4b34:/dev/shm/kafl_mtarral$ find corpus/crash/ -type f -exec hexdump -C {} \;
00000000  ff ff 00 00 6f b8 00                              |....o..|
00000007
00000000  85 a4 13 9f 63 c1 a8 b2  ff 0a 16 00              |....c.......|
0000000c
00000000  76 5b 13 9f 63 c1 a8 b2  ff 0a 16 00              |v[..c.......|
0000000c
00000000  1a 5b 13 9f 63 c1 a8 b2  ff 0a 16 00              |.[..c.......|
0000000c
```

In the context of our test harness, the first byte usually represents the ioctl code.

Therefore, if the first byte varies across the payloads, it suggests that these payloads are triggering unique handler paths.

## Crash logs

The `--log-crashes` option, combined with the redirection of printk messages to the hprintf hypercall, gives us detailed log files for each crash. These logs are stored in the `📂 logs` directory.


```{code-block} shell
---
caption: Displaying payload crash files from the corpus
---
(.venv) mtarral@b49691bd4b34:/dev/shm/kafl_mtarral$ ls -l logs
total 100
-rw-rw-r-- 1 mtarral mtarral 5143 Oct 25 16:21 crash_3f7f7a.log
-rw-rw-r-- 1 mtarral mtarral 1714 Oct 25 16:22 crash_881bd2.log
-rw-rw-r-- 1 mtarral mtarral 5139 Oct 25 16:21 crash_908bfe.log
-rw-rw-r-- 1 mtarral mtarral 2609 Oct 25 16:21 crash_fcdaa4.log
-rw-rw-r-- 1 mtarral mtarral   73 Oct 25 16:21 timeo_05da3a.log
-rw-rw-r-- 1 mtarral mtarral  120 Oct 25 16:22 timeo_153a4e.log
-rw-rw-r-- 1 mtarral mtarral   68 Oct 25 16:21 timeo_1cfa76.log
-rw-rw-r-- 1 mtarral mtarral   63 Oct 25 16:21 timeo_2059ab.log
-rw-rw-r-- 1 mtarral mtarral 5124 Oct 25 16:21 timeo_3f7f7a.log
-rw-rw-r-- 1 mtarral mtarral   75 Oct 25 16:21 timeo_5ad762.log
-rw-rw-r-- 1 mtarral mtarral 2650 Oct 25 16:21 timeo_5d47b8.log
-rw-rw-r-- 1 mtarral mtarral  124 Oct 25 16:21 timeo_72bc3d.log
-rw-rw-r-- 1 mtarral mtarral 2668 Oct 25 16:21 timeo_72cc5a.log
-rw-rw-r-- 1 mtarral mtarral 2690 Oct 25 16:21 timeo_7c2cf3.log
-rw-rw-r-- 1 mtarral mtarral   72 Oct 25 16:21 timeo_828a72.log
-rw-rw-r-- 1 mtarral mtarral 4294 Oct 25 16:21 timeo_908bfe.log
-rw-rw-r-- 1 mtarral mtarral   74 Oct 25 16:21 timeo_9d4034.log
-rw-rw-r-- 1 mtarral mtarral   66 Oct 25 16:21 timeo_acefee.log
-rw-rw-r-- 1 mtarral mtarral   68 Oct 25 16:21 timeo_e87026.log
-rw-rw-r-- 1 mtarral mtarral  117 Oct 25 16:22 timeo_f94aee.log
-rw-rw-r-- 1 mtarral mtarral 4022 Oct 25 16:21 timeo_fcdaa4.log
```

We can identify our 4 crashes log files, as well as timeout logs.

Let's open the first one, `crash_3f7f7a.log`:

```{code-block} shell
---
caption: crash_3f7f7a.log
---
6****Triggering Integer Underflow****
6dvkm: [+] datasize: 1444607
6dvkm: [+] width: -1626121354
6dvkm: [+] Height: -1297563293
6dvkm: [+] datasize: 1444607
6dvkm: [+] data: ääääääääääääääää:¥7~î?à~3:`Bá6
6dvkm: [+] calculated size: 776200999
------------[ cut here ]------------
4WARNING: CPU: 0 PID: 75 at mm/page_alloc.c:4453 __alloc_pages+0x1b2/0x2f0
Modules linked in:c dvkm(O)c
CPU: 0 PID: 75 Comm: fuzz_dvkm Tainted: G           O       6.5.0-00004-g6521682f674d #6
Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS rel-1.12.0-59-gc9ba5276e321-prebuilt.qemu.org 04/01/2014
RIP: 0010:__alloc_pages+0x1b2/0x2f0
Code: 49 89 c6 48 85 c0 0f 84 30 01 00 00 66 90 eb 1f 41 83 fc 0a 0f 86 c7 fe ff ff 80 3d f4 33 a3 01 00 75 09 c6 05 eb 33 a3 01 01 <0f> 0b 45 31 f6 48 8b 44 24 28 65 48 2b 04 25 28 00 00 00 0f 85 20
RSP: 0018:ffffc900001cbe08 EFLAGS: 00010246c
RAX: 0000000000000000 RBX: 0000000000040cc0 RCX: 0000000000000000
RDX: 0000000000000000 RSI: 0000000000000000 RDI: 0000000000040cc0
RBP: 0000000000000000 R08: 0000000000000027 R09: 0000000000000000
R10: 0000000000000008 R11: 203a657a69732064 R12: 0000000000000012
R13: 0000000000000012 R14: ffffffffc0000522 R15: 0000000000000000
FS:  00007fe4272b4740(0000) GS:ffff88800f600000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: 00007fe4273f0000 CR3: 0000000004cdc006 CR4: 00000000001706f0
Call Trace:
 <TASK>
 ? __warn+0x7f/0x130
 ? __alloc_pages+0x1b2/0x2f0
 ? report_bug+0x199/0x1b0
 ? handle_bug+0x3c/0x70
 ? exc_invalid_op+0x18/0x70
 ? asm_exc_invalid_op+0x1a/0x20
 ? Integer_Underflow_IOCTL_Handler.part.0+0x112/0x170 [dvkm]
 ? __alloc_pages+0x1b2/0x2f0
 ? vsnprintf+0x3aa/0x560
 ? Integer_Underflow_IOCTL_Handler.part.0+0x112/0x170 [dvkm]
 __kmalloc_large_node+0x79/0x150
 __kmalloc+0xbb/0x130
 Integer_Underflow_IOCTL_Handler.part.0+0x112/0x170 [dvkm]
 dvkm_ioctl+0x130/0x230 [dvkm]
 proc_reg_unlocked_ioctl+0x52/0xa0
 __x64_sys_ioctl+0x89/0xc0
 do_syscall_64+0x3c/0x90
 entry_SYSCALL_64_after_hwframe+0x6e/0xd8
RIP: 0033:0x7fe4273d1b3f
Code: 00 48 89 44 24 18 31 c0 48 8d 44 24 60 c7 04 24 10 00 00 00 48 89 44 24 08 48 8d 44 24 20 48 89 44 24 10 b8 10 00 00 00 0f 05 <41> 89 c0 3d 00 f0 ff ff 77 1f 48 8b 44 24 18 64 48 2b 04 25 28 00
RSP: 002b:00007ffd5dee4e10 EFLAGS: 00000246c ORIG_RAX: 0000000000000010
RAX: ffffffffffffffda RBX: 0000000000000000 RCX: 00007fe4273d1b3f
RDX: 000055c56318b000 RSI: 00000000c0184401 RDI: 0000000000000003
RBP: 00007ffd5dee4ea0 R08: 0000000000000010 R09: 00007ffd5dee3b80
R10: 0000000000000000 R11: 0000000000000246 R12: 00007ffd5dee4fb8
R13: 000055c5631869e0 R14: 000055c563188d48 R15: 00007fe42751b040
 </TASK>
4---[ end trace 0000000000000000 ]---
1BUG: kernel NULL pointer dereference, address: 0000000000000000
1#PF: supervisor write access in kernel mode
1#PF: error_code(0x0002) - not-present page
6PGD 0 cP4D 0 c
Oops: 0002 [#1] PREEMPT SMP NOPTI
CPU: 0 PID: 75 Comm: fuzz_dvkm Tainted: G        W  O       6.5.0-00004-g6521682f674d #6
Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS rel-1.12.0-59-gc9ba5276e321-prebuilt.qemu.org 04/01/2014
RIP: 0010:memcpy_orig+0x31/0x140
Code: 48 83 fa 20 0f 82 86 00 00 00 40 38 fe 7c 35 48 83 ea 20 48 83 ea 20 4c 8b 06 4c 8b 4e 08 4c 8b 56 10 4c 8b 5e 18 48 8d 76 20 <4c> 89 07 4c 89 4f 08 4c 89 57 10 4c 89 5f 18 48 8d 7f 20 73 d4 83
RSP: 0018:ffffc900001cbec0 EFLAGS: 00010202c
RAX: 0000000000000000 RBX: 0000000051bc1cd9 RCX: 0000000000000011
RDX: 0000000000160abf RSI: ffff888004e00020 RDI: 0000000000000000
RBP: ffff888004e00000 R08: 0fe40fe40fe40fe4 R09: 0fe40fe40fe40fe4
R10: 0fe40fe40fe40fe4 R11: 10e40fe40fe40fe4 R12: 000000002e43e327
R13: 000055c56318b000 R14: ffff888004cf2500 R15: 0000000000000000
FS:  00007fe4272b4740(0000) GS:ffff88800f600000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: 0000000000000000 CR3: 0000000004cdc006 CR4: 00000000001706f0
Call Trace:
 <TASK>
 ? __die+0x1f/0x70
 ? page_fault_oops+0x156/0x420
 ? search_exception_tables+0x37/0x50
 ? fixup_exception+0x21/0x310
 ? exc_page_fault+0x69/0x150
 ? asm_exc_page_fault+0x26/0x30
 ? memcpy_orig+0x31/0x140
 Integer_Underflow_IOCTL_Handler.part.0+0x124/0x170 [dvkm]
 dvkm_ioctl+0x130/0x230 [dvkm]
 proc_reg_unlocked_ioctl+0x52/0xa0
 __x64_sys_ioctl+0x89/0xc0
 do_syscall_64+0x3c/0x90
 entry_SYSCALL_64_after_hwframe+0x6e/0xd8
RIP: 0033:0x7fe4273d1b3f
Code: 00 48 89 44 24 18 31 c0 48 8d 44 24 60 c7 04 24 10 00 00 00 48 89 44 24 08 48 8d 44 24 20 48 89 44 24 10 b8 10 00 00 00 0f 05 <41> 89 c0 3d 00 f0 ff ff 77 1f 48 8b 44 24 18 64 48 2b 04 25 28 00
RSP: 002b:00007ffd5dee4e10 EFLAGS: 00000246c ORIG_RAX: 0000000000000010
RAX: ffffffffffffffda RBX: 0000000000000000 RCX: 00007fe4273d1b3f
RDX: 000055c56318b000 RSI: 00000000c0184401 RDI: 0000000000000003
RBP: 00007ffd5dee4ea0 R08: 0000000000000010 R09: 00007ffd5dee3b80
R10: 0000000000000000 R11: 0000000000000246 R12: 00007ffd5dee4fb8
R13: 000055c5631869e0 R14: 000055c563188d48 R15: 00007fe42751b040
 </TASK>
Modules linked in:c dvkm(O)c
CR2: 0000000000000000
4---[ end trace 0000000000000000 ]---
```

We can identify that `RIP` is at `memcpy_orig()`, called from our DVKM module by ` Integer_Underflow_IOCTL_Handler.part.0+0x124/0x170 [dvkm]`.

:::{code-block} shell
---
caption: struct dvkm_obj content to trigger the integer underflow
---
dvkm: [+] datasize: 1444607
dvkm: [+] width: -1626121354
dvkm: [+] Height: -1297563293
dvkm: [+] datasize: 1444607
dvkm: [+] data: ääääääääääääääää:¥7~î?à~3:`Bá6
:::

::::{Note}
The number that you can sometimes see at the beginning of a log message is simply the kernel logging level which hasn't been translated into a proper string
by the logging facility.

:::{code-block} C
---
caption: include/linux/kern_levels.h
---
#define KERN_EMERG	KERN_SOH "0"	/* system is unusable */
#define KERN_ALERT	KERN_SOH "1"	/* action must be taken immediately */
#define KERN_CRIT	KERN_SOH "2"	/* critical conditions */
#define KERN_ERR	KERN_SOH "3"	/* error conditions */
#define KERN_WARNING	KERN_SOH "4"	/* warning conditions */
#define KERN_NOTICE	KERN_SOH "5"	/* normal but significant condition */
#define KERN_INFO	KERN_SOH "6"	/* informational */
#define KERN_DEBUG	KERN_SOH "7"	/* debug-level messages */
:::
::::

## `kafl debug`

The `kafl debug` subcommand provides various utilities for debugging your fuzzing campaign.

By using this subcommand, you can replay payloads to better understand the control flow leading to a crash, verify the stability and determinism of a payload, and even debug the guest state live while replaying the payload.

In this section, we'll explore two key [`actions`](../../../reference/fuzzer_configuration.md#action) provided by `kafl debug`:

- `single`
- `gdb`

### Action `single`

The `single` action let's you replay a single payload and observe its results:

The payload should be specified throught the [`--input`](../../../reference/fuzzer_configuration.md#input) parameter.

:::{Important}
When replaying a payload from an previous kAFL run at $KAFL_WORKDIR, it is recommended to use [`--resume`](../../../reference/fuzzer_configuration.md#resume) so that the tool will use the exact same snapshot and page cache as in the fuzzing run. This improves our odds at reproducing the crash. If the workdir does not exist anymore or the snapshot is not found, running kafl single without `--resume` will simply boot a new VM with the given configuration and execute the agent a single time with the given input.
:::

:::{code-block} shell
(.venv) mtarral@b49691bd4b34:~/kafl/kafl/examples/linux-user/dvkm$ kafl debug \
    --resume \
    --action single \
    --input /dev/shm/kafl_mtarral/corpus/crash/payload_00030

    __                        __  ___    ________
   / /_____  _________  ___  / / /   |  / ____/ /
  / //_/ _ \/ ___/ __ \/ _ \/ / / /| | / /_  / /
 / ,< /  __/ /  / / / /  __/ / / ___ |/ __/ / /___
/_/|_|\___/_/  /_/ /_/\___/_/ /_/  |_/_/   /_____/
===================================================

<< kAFL Debugger >>

No trace region configured! Intel PT disabled!
Execute payload /dev/shm/kafl_mtarral/corpus/crash/payload_00030..
Worker-1337 Launching virtual machine...
/home/mtarral/kafl/kafl/qemu/x86_64-softmmu/qemu-system-x86_64
        -enable-kvm
        -machine kAFL64-v1
        -cpu kAFL64-Hypervisor-v1,+vmx
        -no-reboot
        -net none
        -display none
        -chardev socket,server,id=nyx_socket,path=/dev/shm/kafl_mtarral/interface_1337
        -device nyx,chardev=nyx_socket,workdir=/dev/shm/kafl_mtarral,worker_id=1337,bitmap_size=65536,input_buffer_size=131072,sharedir=/home/mtarral/kafl/kafl/examples/linux-user/dvkm/sharedir
        -device isa-serial,chardev=kafl_serial
        -chardev file,id=kafl_serial,mux=on,path=/dev/shm/kafl_mtarral/serial_1337.log
        -m 256
        -kernel /home/mtarral/kafl/kafl/examples/linux-user/linux_kafl_agent/arch/x86/boot/bzImage
        -initrd /home/mtarral/kafl/kafl/examples/linux-user/scripts/kafl_initrd.cpio.gz
        -append root=/dev/vda1 rw nokaslr oops=panic nopti mitigations=off console=ttyS0 earlyprintk=serial,ttyS0 ignore_loglevel
        -fast_vm_reload path=/dev/shm/kafl_mtarral/snapshot/,load=on
qemu-system-x86_64: warning: host doesn't support requested feature: CPUID.07H:EBX.hle [bit 4]
qemu-system-x86_64: warning: host doesn't support requested feature: CPUID.07H:EBX.rtm [bit 11]
[QEMU-NYX] Waiting for snapshot to start fuzzing...
6****Triggering Integer Overflow****
6dvkm: [+] datasize: 1444607
6dvkm: [+] width: -1626121446
6dvkm: [+] Height: -1297563293
6dvkm: [+] datasize: 1444607
6dvkm: [+] data: ««««««««««««««««««««««««««««««««««««««««««««««««««
6dvkm: [+] calculated size: 1371282556
------------[ cut here ]------------
4WARNING: CPU: 0 PID: 75 at mm/page_alloc.c:4453 __alloc_pages+0x1b2/0x2f0
c
CPU: 0 PID: 75 Comm: fuzz_dvkm Tainted: G           O       6.5.0-00004-g6521682f674d #6
Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS rel-1.12.0-59-gc9ba5276e321-prebuilt.qemu.org 04/01/2014
RIP: 0010:__alloc_pages+0x1b2/0x2f0
Code: 49 89 c6 48 85 c0 0f 84 30 01 00 00 66 90 eb 1f 41 83 fc 0a 0f 86 c7 fe ff ff 80 3d f4 33 a3 01 00 75 09 c6 05 eb 33 a3 01 01 <0f> 0b 45 31 f6 48 8b 44 24 28 65 48 2b 04 25 28 00 00 00 0f 85 20
c
RAX: 0000000000000000 RBX: 0000000000040cc0 RCX: 0000000000000000
RDX: 0000000000000000 RSI: 0000000000000000 RDI: 0000000000040cc0
RBP: 0000000000000000 R08: 0000000000000028 R09: 0000000000000000
R10: 0000000000000009 R11: 203a657a69732064 R12: 0000000000000013
R13: 0000000000000013 R14: ffffffffc00003aa R15: 0000000000000000
FS:  00007fe4272b4740(0000) GS:ffff88800f600000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: 00007fe4273f0000 CR3: 0000000004cdc006 CR4: 00000000001706f0
Call Trace:
 <TASK>
 ? __warn+0x7f/0x130
 ? __alloc_pages+0x1b2/0x2f0
 ? report_bug+0x199/0x1b0
 ? handle_bug+0x3c/0x70
 ? exc_invalid_op+0x18/0x70
 ? asm_exc_invalid_op+0x1a/0x20
 ? Integer_Overflow_IOCTL_Handler.part.0+0x10a/0x160 [dvkm]
 ? __alloc_pages+0x1b2/0x2f0
 ? vsnprintf+0x3aa/0x560
 ? Integer_Overflow_IOCTL_Handler.part.0+0x10a/0x160 [dvkm]
 __kmalloc_large_node+0x79/0x150
 __kmalloc+0xbb/0x130
 Integer_Overflow_IOCTL_Handler.part.0+0x10a/0x160 [dvkm]
 dvkm_ioctl+0x16a/0x230 [dvkm]
 proc_reg_unlocked_ioctl+0x52/0xa0
 __x64_sys_ioctl+0x89/0xc0
 do_syscall_64+0x3c/0x90
 entry_SYSCALL_64_after_hwframe+0x6e/0xd8
RIP: 0033:0x7fe4273d1b3f
Code: 00 48 89 44 24 18 31 c0 48 8d 44 24 60 c7 04 24 10 00 00 00 48 89 44 24 08 48 8d 44 24 20 48 89 44 24 10 b8 10 00 00 00 0f 05 <41> 89 c0 3d 00 f0 ff ff 77 1f 48 8b 44 24 18 64 48 2b 04 25 28 00
c ORIG_RAX: 0000000000000010
RAX: ffffffffffffffda RBX: 0000000000000000 RCX: 00007fe4273d1b3f
RDX: 000055c56318b000 RSI: 00000000c0184400 RDI: 0000000000000003
RBP: 00007ffd5dee4ea0 R08: 0000000000000010 R09: 00007ffd5dee3b80
R10: 0000000000000000 R11: 0000000000000246 R12: 00007ffd5dee4fb8
R13: 000055c5631869e0 R14: 000055c563188d48 R15: 00007fe42751b040
 </TASK>
4---[ end trace 0000000000000000 ]---
1BUG: kernel NULL pointer dereference, address: 0000000000000000
1#PF: supervisor write access in kernel mode
1#PF: error_code(0x0002) - not-present page
c
Oops: 0002 [#1] PREEMPT SMP NOPTI
CPU: 0 PID: 75 Comm: fuzz_dvkm Tainted: G        W  O       6.5.0-00004-g6521682f674d #6
Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS rel-1.12.0-59-gc9ba5276e321-prebuilt.qemu.org 04/01/2014
RIP: 0010:memcpy_orig+0x31/0x140
Code: 48 83 fa 20 0f 82 86 00 00 00 40 38 fe 7c 35 48 83 ea 20 48 83 ea 20 4c 8b 06 4c 8b 4e 08 4c 8b 56 10 4c 8b 5e 18 48 8d 76 20 <4c> 89 07 4c 89 4f 08 4c 89 57 10 4c 89 5f 18 48 8d 7f 20 73 d4 83
c
RAX: 0000000000000000 RBX: 0000000051bc1c7c RCX: 0000000000000012
RDX: 0000000000160abf RSI: ffff888004e00020 RDI: 0000000000000000
RBP: ffff888004e00000 R08: abababababababab R09: abababababababab
R10: abababababababab R11: abababababababab R12: 000000009f135b1a
R13: 000055c56318b000 R14: ffff888004cf2500 R15: 0000000000000000
FS:  00007fe4272b4740(0000) GS:ffff88800f600000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: 0000000000000000 CR3: 0000000004cdc006 CR4: 00000000001706f0
Call Trace:
 <TASK>
 ? __die+0x1f/0x70
 ? page_fault_oops+0x156/0x420
 ? search_exception_tables+0x37/0x50
 ? fixup_exception+0x21/0x310
 ? exc_page_fault+0x69/0x150
 ? asm_exc_page_fault+0x26/0x30
 ? memcpy_orig+0x31/0x140
 Integer_Overflow_IOCTL_Handler.part.0+0x11c/0x160 [dvkm]
 dvkm_ioctl+0x16a/0x230 [dvkm]
 proc_reg_unlocked_ioctl+0x52/0xa0
 __x64_sys_ioctl+0x89/0xc0
 do_syscall_64+0x3c/0x90
 entry_SYSCALL_64_after_hwframe+0x6e/0xd8
RIP: 0033:0x7fe4273d1b3f
Code: 00 48 89 44 24 18 31 c0 48 8d 44 24 60 c7 04 24 10 00 00 00 48 89 44 24 08 48 8d 44 24 20 48 89 44 24 10 b8 10 00 00 00 0f 05 <41> 89 c0 3d 00 f0 ff ff 77 1f 48 8b 44 24 18 64 48 2b 04 25 28 00
c ORIG_RAX: 0000000000000010
RAX: ffffffffffffffda RBX: 0000000000000000 RCX: 00007fe4273d1b3f
RDX: 000055c56318b000 RSI: 00000000c0184400 RDI: 0000000000000003
RBP: 00007ffd5dee4ea0 R08: 0000000000000010 R09: 00007ffd5dee3b80
R10: 0000000000000000 R11: 0000000000000246 R12: 00007ffd5dee4fb8
R13: 000055c5631869e0 R14: 000055c563188d48 R15: 00007fe42751b040
 </TASK>
c
CR2: 0000000000000000
4---[ end trace 0000000000000000 ]---
Exit reason: crash
Feedback Hash: 908bfe7fc5777d10
Worker-1337 Shutting down Qemu after 0 execs..
qemu-system-x86_64: terminating on signal 15 from pid 1303499 (/home/mtarral/kafl/kafl/.venv/bin/python3)
Done. Check logs for details.
:::

We just replayed payload `30` and got the full log output directly on stdout ! 
And kAFL confirmed that it received a `crash` event.

We could modify our target, harness or tweak the fuzzer settings to see if this payload still triggers a crash.

:::{Note}
It could be beneficial to keep this payload for future use.

For example when the target code will be fixed, we could replay that payload and use `kafl debug` as a regression test tool.
:::

### Action `gdb`

The `gdb` action is particularly valuable for deep-diving into the issues discovered during fuzzing.

This action working similar to `single`, but QEMU is started in `gdbserver` mode, allowing it to act as a server for the GDB debugger. This means you can interact with the target application in real-time as the payload is being executed.

The use of GDB provides fine-grained control over the execution of the program and allows you to inspect the program's state, variables, and call stack, offering a clear view into what led to a particular crash or unexpected behavior.

Upon executing this command, QEMU will pause its execution and wait for a GDB client to connect. Once connected, you can use all the GDB commands to step through code, set breakpoints, and inspect memory and variables, thus enabling a thorough analysis of the crash scenario.

:::{code-block} shell
(.venv) mtarral@b49691bd4b34:~/kafl/kafl/examples/linux-user/dvkm$ kafl debug \
    --resume \
    --action gdb \
    --input /dev/shm/kafl_mtarral/corpus/crash/payload_00030

    __                        __  ___    ________
   / /_____  _________  ___  / / /   |  / ____/ /
  / //_/ _ \/ ___/ __ \/ _ \/ / / /| | / /_  / /
 / ,< /  __/ /  / / / /  __/ / / ___ |/ __/ / /___
/_/|_|\___/_/  /_/ /_/\___/_/ /_/  |_/_/   /_____/
===================================================

<< kAFL Debugger >>

No trace region configured! Intel PT disabled!
Starting Qemu + GDB with payload /dev/shm/kafl_mtarral/corpus/crash/payload_00030
Connect with gdb to release guest from reset (localhost:1234)
Worker-1337 Launching virtual machine...
/home/mtarral/kafl/kafl/qemu/x86_64-softmmu/qemu-system-x86_64
        -enable-kvm
        -machine kAFL64-v1
        -cpu kAFL64-Hypervisor-v1,+vmx
        -no-reboot
        -net none
        -display none
        -chardev socket,server,id=nyx_socket,path=/dev/shm/kafl_mtarral/interface_1337
        -device nyx,chardev=nyx_socket,workdir=/dev/shm/kafl_mtarral,worker_id=1337,bitmap_size=65536,input_buffer_size=131072,sharedir=/home/mtarral/kafl/kafl/examples/linux-user/dvkm/sharedir
        -device isa-serial,chardev=kafl_serial
        -chardev file,id=kafl_serial,mux=on,path=/dev/shm/kafl_mtarral/serial_1337.log
        -m 256
        -s
        -S
        -kernel /home/mtarral/kafl/kafl/examples/linux-user/linux_kafl_agent/arch/x86/boot/bzImage
        -initrd /home/mtarral/kafl/kafl/examples/linux-user/scripts/kafl_initrd.cpio.gz
        -append root=/dev/vda1 rw nokaslr oops=panic nopti mitigations=off console=ttyS0 earlyprintk=serial,ttyS0 ignore_loglevel
        -fast_vm_reload path=/dev/shm/kafl_mtarral/snapshot/,load=on
qemu-system-x86_64: warning: host doesn't support requested feature: CPUID.07H:EBX.hle [bit 4]
qemu-system-x86_64: warning: host doesn't support requested feature: CPUID.07H:EBX.rtm [bit 11]
[QEMU-NYX] Waiting for snapshot to start fuzzing...

:::

Now we need to connect to the local GDB server and release the execution.

But before we do that, we need to make sure we can load the debug symbols for both the Linux kernel and our DVKM module.

If you look at the Makefile, you can observe that it preconfigures the kernel:

:::{code-block} Makefile
---
caption: Makefile rule to build the kernel bzImage
---
$(LINUX_AGENT_BZIMAGE):
	$(MAKE) -C $(LINUX_AGENT_DIR) x86_64_defconfig
	cd $(LINUX_AGENT_DIR) && ./scripts/config --disable MODULE_SIG
	cd $(LINUX_AGENT_DIR) && ./scripts/config --enable DEBUG_INFO_DWARF5
	cd $(LINUX_AGENT_DIR) && ./scripts/config --enable GDB_SCRIPTS
:::

- [`DEBUG_INFO_DWARF5`](https://cateee.net/lkddb/web-lkddb/DEBUG_INFO_DWARF5.html): generates and includes DWARF5 debug info in the kernel image.
- [`GDB_SCRIPTS`](https://cateee.net/lkddb/web-lkddb/GDB_SCRIPTS.html): creates links to helper GDB scripts when loading `vmlinux` to provide additional functions useful to analyze a running Linux instance.

Let's create a new shell, move into `📂 linux_kafl_agent` 

:::{code-block} shell
(.venv) cd $EXAMPLES_ROOT/linux-user/linux_kafl_agent
:::

And invoke GDB to load the symbols and connect the to remote target:
:::{code-block} shell
---
caption: GDB client command line
---
(.venv) gdb -q vmlinux \
    -ex 'target remote :1234' \
    -ex 'lx-symbols ../dvkm/Damn_Vulnerable_Kernel_Module'
Reading symbols from vmlinux...
Remote debugging using :1234
0x000055561177f34d in ?? ()
loading vmlinux
scanning for modules in /home/mtarral/kafl/kafl/examples/linux-user/dvkm/Damn_Vulnerable_Kernel_Module
scanning for modules in /home/mtarral/kafl/kafl/examples/linux-user/linux_kafl_agent
loading @0xffffffffc0000000: /home/mtarral/kafl/kafl/examples/linux-user/dvkm/Damn_Vulnerable_Kernel_Module/dvkm.ko
(gdb)
:::

From there, you are now in a debugging session with an active target. You can place your breakpoints, and have access to all kernel symbols, as well as dvkm once.

Let's try to put a breakpoint on `dvkm_ioctl` and `oops_enter`, and continue the execution:

:::{code-block} shell
---
caption: Adding breakpoints
---
(gdb) hbreak dvkm_ioctl
Hardware assisted breakpoint 1 at 0xffffffffc0000c30: file /home/mtarral/kafl/kafl/examples/linux-user/dvkm/Damn_Vulnerable_Kernel_Module/dvkm.c, line 410.
(gdb) hbreak oops_enter
Hardware assisted breakpoint 2 at 0xffffffff8114c660: file kernel/panic.c, line 623.
(gdb) c
:::

:::{code-block} shell
---
caption: Debugging dvkm_ioctl
---
(gdb) l
405             return 0;
406     }
407
408     //IOCTL handler, this calls various vulnerable functions.
409     noinline long dvkm_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
410     {
411             int status = -EINVAL;
412             void __user *arg_user;
413
414             if (arg == 0) {
(gdb) disas
Dump of assembler code for function dvkm_ioctl:
=> 0xffffffffc0000c30 <+0>:     endbr64
   0xffffffffc0000c34 <+4>:     test   %rdx,%rdx
   0xffffffffc0000c37 <+7>:     je     0xffffffffc0000d65 <dvkm_ioctl+309>
   0xffffffffc0000c3d <+13>:    push   %rbp
   0xffffffffc0000c3e <+14>:    mov    %rdx,%rbp
   0xffffffffc0000c41 <+17>:    cmp    $0xc0184406,%esi
   0xffffffffc0000c47 <+23>:    je     0xffffffffc0000dff <dvkm_ioctl+463>
   0xffffffffc0000c4d <+29>:    ja     0xffffffffc0000c91 <dvkm_ioctl+97>
   0xffffffffc0000c4f <+31>:    cmp    $0xc0184402,%esi
   0xffffffffc0000c55 <+37>:    je     0xffffffffc0000e18 <dvkm_ioctl+488>
   0xffffffffc0000c5b <+43>:    jbe    0xffffffffc0000d1e <dvkm_ioctl+238>
   0xffffffffc0000c61 <+49>:    cmp    $0xc0184403,%esi
   0xffffffffc0000c67 <+55>:    je     0xffffffffc0000d9f <dvkm_ioctl+367>
   0xffffffffc0000c6d <+61>:    cmp    $0xc0184405,%esi
   0xffffffffc0000c73 <+67>:    jne    0xffffffffc0000c89 <dvkm_ioctl+89>
   0xffffffffc0000c75 <+69>:    mov    $0xffffffffc00104a0,%rdi
   0xffffffffc0000c7c <+76>:    call   0xffffffff8127e7a0 <_printk>
   0xffffffffc0000c81 <+81>:    mov    %rbp,%rdi
   0xffffffffc0000c84 <+84>:    call   0xffffffffc0000a20 <Stack_OOBR_IOCTL_Handler>
   0xffffffffc0000c89 <+89>:    xor    %eax,%eax
   0xffffffffc0000c8b <+91>:    pop    %rbp
   0xffffffffc0000c8c <+92>:    ret
:::

To continue playing with our breakpoints, let's move to `oops_enter` (confirming that the current payload is triggering a crash), and dump the stack:

:::{code-block} shell
---
caption: Dumping the stack on oops_enter
---
Breakpoint 2, oops_enter () at kernel/panic.c:623
623     {
(gdb) c
(gdb) bt
#0  oops_enter () at kernel/panic.c:623
#1  0xffffffff810812dc in oops_begin () at arch/x86/kernel/dumpstack.c:338
#2  0xffffffff81081cfe in die_addr (str=str@entry=0xffff888007f27b2c "general protection fault, probably for non-canonical address 0xe0000be0d732a202", regs=regs@entry=0xffff888007f27bb8, err=err@entry=0,
    gp_addr=-2305829948902694398) at arch/x86/kernel/dumpstack.c:454
#3  0xffffffff83c43378 in __exc_general_protection (error_code=0, regs=0xffff888007f27bb8) at arch/x86/kernel/traps.c:784
#4  exc_general_protection (regs=0xffff888007f27bb8, error_code=0) at arch/x86/kernel/traps.c:729
#5  0xffffffff83e01206 in asm_exc_general_protection () at ./arch/x86/include/asm/idtentry.h:564
#6  0xffff888007f27e80 in ?? ()
#7  0xffffffff86060000 in hprintf_buffer ()
#8  0x1ffff11000fe4f90 in ?? ()
#9  0xffffffff8605f044 in hprintf_buffer ()
#10 0xffffffff8605f012 in hprintf_buffer ()
#11 0x00007f06b9951016 in ?? ()
#12 0x1ffffffff092a03d in ?? ()
#13 0xffffffffc0010175 in ?? ()
#14 0x203a61746164205d in ?? ()
#15 0xdffffc0000000000 in ?? ()
#16 0x00000fe0d732a202 in ?? ()
#17 0x00320a00ffffff04 in ?? ()
#18 0x0000000000000005 in fixed_percpu_data ()
#19 0x0000000000000000 in ?? ()
:::

:::{Important}
We need to use GDB hardware breakpoints, as software breakpoints in QEMU's embedded GDB server seems unrealiable.
:::
:::{Note}
To reach the `dvkm_ioctl` hardware breakpoint, we had to send a `CTRL-C` to the GDB client.
The execution was hanging somewhere, for reasons that are not clear at the time of this writing.
:::
:::{Note}
Additionaly, in order to load the symbols reliably, at the same location, Kernel `ASLR` (_Address Space Layout Randomization_) had to be disabled.

Have a look at the `kafl.yaml` `qemu_append` line, where [`nokaslr`](https://www.kernel.org/doc/html/v4.14/admin-guide/kernel-parameters.html) option is set.
:::

Hopefully by now, you should have a better understanding of the kAFL workdir's corpus directory, the captured logs and how to interpret them, as well as having the capacity to replay payloads as you will !

The next section will focus on improving the fuzzing campaign and finding more crashes by compiling our target under `KASAN`, stay tuned !
