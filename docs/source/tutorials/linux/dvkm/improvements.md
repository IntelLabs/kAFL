# 6 - Improvements: KASAN

We have room to improve our current fuzzing setup.

In fact, the Linux kernel can be compiled with [`KASAN`](https://cateee.net/lkddb/web-lkddb/KASAN.html) (_Kernel Address Sanitizer_), which is a dynamic memory safety error detector.

It provides a fast and comprehensive solution for finding use-after-free and out-of-bounds bugs, with a compile-time instrumentation for checking every memory access.

## Compiling with KASAN

Let's have a quick look at our Makefile again:

:::{code-block} makefile
---
caption: Makefile rule to build the kernel bzImage
linenos: yes
emphasize-lines: 6-9
---
$(LINUX_AGENT_BZIMAGE):
	$(MAKE) -C $(LINUX_AGENT_DIR) x86_64_defconfig
	cd $(LINUX_AGENT_DIR) && ./scripts/config --disable MODULE_SIG
	cd $(LINUX_AGENT_DIR) && ./scripts/config --enable DEBUG_INFO_DWARF5
	cd $(LINUX_AGENT_DIR) && ./scripts/config --enable GDB_SCRIPTS
ifdef DVKM_KASAN
	cd $(LINUX_AGENT_DIR) && ./scripts/config --enable KASAN
	cd $(LINUX_AGENT_DIR) && ./scripts/config --enable KASAN_INLINE
endif
:::

And recompile our target with `KASAN` checks enabled:

:::{code-block} shell
(.venv) cd $EXAMPLES_ROOT/linux-user/dvkm
(.venv) make clean && make DVKM_KASAN=y
:::

Thanks to the `KASAN` kAFL event inserted into [`kasan_report`](agent.md#kernel-crash), we should detect new memory corruption crashes in kAFL:

:::{code-block} diff
---
caption: Modified mm/kasan/report.c
---
 #include <asm/sections.h>

+#include <asm/nyx_api.h>
+
 #include "kasan.h"
 #include "../slab.h"

@@ -588,6 +590,7 @@ bool kasan_report(const void *addr, size_t size, bool is_write,
        print_report(&info);

        end_report(&irq_flags, (void *)addr, is_write);
+       kAFL_hypercall(HYPERCALL_KAFL_KASAN, 0);

 out:
        user_access_restore(ua_flags);
:::

## Running an enhanced campaign

We can now run our fuzzing campaign again, and watch for the results.

In just 30 seconds, kAFL was able to find `8` `KASAN` related crashes:

:::{code-block} shell
  ┏━┫▌kAFL Grand UI▐┣━┓
┏━┻━━━━━━━━━━━━━━━━━━━┻━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Runtime:    0m33s │ #Execs:    249.7K │ Stability:     6% │ Workers:   20/64 ┃
┃                   │ CurExec/s:   9824 │ Funkiness:   0.0% │ CPU Use:      0% ┃
┃ Est. Done:    40% │ AvgExec/s:   7529 │ Timeouts:    0.1% │ RAM Use:      1% ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
┏━━❮❰ Progress ❱❯━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃                                                                              ┃
┃ Paths:            │ Bitmap:           │ Findings:                            ┃
┃  Total:        38 │                   │  Crash:           5 (N/A)      0m27s ┃
┃  Seeds:        23 │  Edges:       100 │  AddSan:          8 (N/A)      0m23s ┃
┃  Favs:         38 │  Blocks:      150 │  Timeout:        12 (N/A)      0m08s ┃
┃  Norm:          0 │  p(col):     0.2% │  Regular:        38 (N/A)      0m15s ┃
┠──────────────────────────────────────────────────────────────────────────────┨
:::

## Viewing a KASAN report

We can already stop our fuzzing campaign by now, and check into `📂 $KAFL_WORKDIR/corpus/kasan`:

:::{code-block} shell
(.venv) ls -l $KAFL_WORKDIR/corpus/kasan
total 32
-rw-r--r-- 1 mtarral mtarral 12 Oct 26 06:40 payload_00026
-rw-r--r-- 1 mtarral mtarral 12 Oct 26 06:40 payload_00036
-rw-r--r-- 1 mtarral mtarral 12 Oct 26 06:40 payload_00038
-rw-r--r-- 1 mtarral mtarral 12 Oct 26 06:40 payload_00039
-rw-r--r-- 1 mtarral mtarral 12 Oct 26 06:40 payload_00040
-rw-r--r-- 1 mtarral mtarral 12 Oct 26 06:40 payload_00044
-rw-r--r-- 1 mtarral mtarral 12 Oct 26 06:40 payload_00048
-rw-r--r-- 1 mtarral mtarral  1 Oct 26 06:40 payload_00059
:::

Our `8` crashing `KASAN` payloads are regrouped here.

Let's now have a look at the `hprintf` logs associated with a `KASAN` crash:

:::{code-block} shell
(.venv) ls -l $KAFL_WORKDIR/logs/kasan_*.log
-rw-rw-r-- 1 mtarral mtarral 3376 Oct 26 06:40 /dev/shm/kafl_mtarral/logs/kasan_020e1d.log
-rw-rw-r-- 1 mtarral mtarral 3565 Oct 26 06:40 /dev/shm/kafl_mtarral/logs/kasan_1bfee1.log
-rw-rw-r-- 1 mtarral mtarral 2773 Oct 26 06:40 /dev/shm/kafl_mtarral/logs/kasan_2253d6.log
-rw-rw-r-- 1 mtarral mtarral 3101 Oct 26 06:40 /dev/shm/kafl_mtarral/logs/kasan_79191f.log
-rw-rw-r-- 1 mtarral mtarral 3517 Oct 26 06:40 /dev/shm/kafl_mtarral/logs/kasan_9251db.log
-rw-rw-r-- 1 mtarral mtarral 3365 Oct 26 06:40 /dev/shm/kafl_mtarral/logs/kasan_a034fe.log
-rw-rw-r-- 1 mtarral mtarral 3514 Oct 26 06:40 /dev/shm/kafl_mtarral/logs/kasan_b91a90.log
-rw-rw-r-- 1 mtarral mtarral 3388 Oct 26 06:40 /dev/shm/kafl_mtarral/logs/kasan_f0e92d.log
:::

Let's now open the first one: `kasan_020e1d.log`:

:::{code-block} shell
6****Triggering use after free****
6dvkm: [+] datasize: 16
3==================================================================
3BUG: KASAN: slab-out-of-bounds in string+0x2a0/0x320
3Read of size 1 at addr ffff888008511390 by task fuzz_dvkm/75
3
3CPU: 0 PID: 75 Comm: fuzz_dvkm Tainted: G           O       6.5.0-00004-g6521682f674d #11
3Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS rel-1.12.0-59-gc9ba5276e321-prebuilt.qemu.org 04/01/2014
3Call Trace:
3 <TASK>
3 dump_stack_lvl+0x37/0x50
3 print_report+0xcc/0x620
3 ? string+0x2a0/0x320
3 kasan_report+0xb0/0xf0
3 ? string+0x2a0/0x320
3 string+0x2a0/0x320
3 ? __x64_sys_ioctl+0x12d/0x1a0
3 ? __pfx_string+0x10/0x10
3 ? __pte_offset_map_lock+0xdf/0x1e0
3 vsnprintf+0x809/0x1600
3 ? __pfx_vsnprintf+0x10/0x10
3 ? ioctl_has_perm.constprop.0.isra.0+0x274/0x440
3 _printk+0xce/0x120
3 ? __pfx__printk+0x10/0x10
3 ? kasan_set_track+0x25/0x30
3 ? __kasan_kmalloc+0x7f/0x90
3 Use_after_free_IOCTL_Handler.part.0+0x71/0xb0 [dvkm]
3 dvkm_ioctl+0x1b2/0x230 [dvkm]
3 proc_reg_unlocked_ioctl+0x1a1/0x270
3 __x64_sys_ioctl+0x12d/0x1a0
3 do_syscall_64+0x3c/0x90
3 entry_SYSCALL_64_after_hwframe+0x6e/0xd8
3RIP: 0033:0x7fec88b37b3f
3Code: 00 48 89 44 24 18 31 c0 48 8d 44 24 60 c7 04 24 10 00 00 00 48 89 44 24 08 48 8d 44 24 20 48 89 44 24 10 b8 10 00 00 00 0f 05 <41> 89 c0 3d 00 f0 ff ff 77 1f 48 8b 44 24 18 64 48 2b 04 25 28 00
3RSP: 002b:00007ffe5d840a80 EFLAGS: 00000246c ORIG_RAX: 0000000000000010
3RAX: ffffffffffffffda RBX: 0000000000000000 RCX: 00007fec88b37b3f
3RDX: 000056144fe16000 RSI: 00000000c018440a RDI: 0000000000000003
3RBP: 00007ffe5d840b10 R08: 0000000000000010 R09: 00007ffe5d83f7f0
3R10: 0000000000000000 R11: 0000000000000246 R12: 00007ffe5d840c28
3R13: 000056144fe119e0 R14: 000056144fe13d48 R15: 00007fec88c81040
3 </TASK>
3
3Allocated by task 75:
 kasan_save_stack+0x22/0x50
 kasan_set_track+0x25/0x30
 __kasan_kmalloc+0x7f/0x90
 __kmalloc+0x5a/0x140
 Use_after_free_IOCTL_Handler.part.0+0x2f/0xb0 [dvkm]
 dvkm_ioctl+0x1b2/0x230 [dvkm]
 proc_reg_unlocked_ioctl+0x1a1/0x270
 __x64_sys_ioctl+0x12d/0x1a0
 do_syscall_64+0x3c/0x90
 entry_SYSCALL_64_after_hwframe+0x6e/0xd8
3
3The buggy address belongs to the object at ffff888008511380
 which belongs to the cache kmalloc-16 of size 16
3The buggy address is located 0 bytes to the right of
 allocated 16-byte region [ffff888008511380, ffff888008511390)
3
3The buggy address belongs to the physical page:
4page:(____ptrval____) refcount:1 mapcount:0 mapping:0000000000000000 index:0x0 pfn:0x8511
4flags: 0x100000000000200(slab|node=0|zone=1)
4page_type: 0xffffffff()
4raw: 0100000000000200 ffff8880064413c0 dead000000000122 0000000000000000
4raw: 0000000000000000 0000000080800080 00000001ffffffff 0000000000000000
4page dumped because: kasan: bad access detected
3
3Memory state around the buggy address:
3 ffff888008511280: 00 00 fc fc 00 00 fc fc 00 00 fc fc 00 00 fc fc
3 ffff888008511300: 00 04 fc fc 00 00 fc fc 00 03 fc fc 00 00 fc fc
3>ffff888008511380: 00 00 fc fc fb fb fc fc fb fb fc fc fb fb fc fc
3                         ^
3 ffff888008511400: 00 06 fc fc 00 04 fc fc 00 00 fc fc 00 04 fc fc
3 ffff888008511480: 00 07 fc fc 00 04 fc fc 00 04 fc fc 00 04 fc fc
3==================================================================
4Disabling lock debugging due to kernel taint
:::

This is a **use-after-free** crash !

Feel free to investigate the detailed KASAN report, or consult the official [documentation](https://www.kernel.org/doc/html/v4.14/dev-tools/kasan.html)

This marks the end of the DVKM tutorial ! 🎉

You should have a better understanding of kAFL, a solid workflow to fuzz your Linux kernel modules and insights how to debug them !
