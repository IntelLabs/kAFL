# kAFL/Nyx Hypercall API

For fuzzing in kAFL/Nyx, the guest VM issues special hypercalls to bootstrap and
coordinate the execution of the fuzzing harness with the fuzzer frontend.

This approach offers a minimal low-level interface that can be used to take
control and start injecting inputs at any point in VM guest execution.

The hypercall API can be found in the [nyx_api.h](https://github.com/IntelLabs/kafl.targets/blob/master/nyx_api.h) C header.

The following hypercalls should be prefixed by `HYPERCALL_KAFL_`.

## Essential hypercalls

### `ACQUIRE` / `RELEASE`

They are used to:

- enable / disable feedback collection
- perform the initial handshake with the host frontend


```{code-block} C
---
caption: Example
---
// 🤝 kAFL handshake 
kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);
kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
// kAFL configuration, filters, etc...
// 🟢 Enable feedback collection
kAFL_hypercall(KAFL_HYPERCALL_ACQUIRE);
// ⚡call target func ...
// ⚪ Disable feedback collection
kAFL_hypercall(KAFL_HYPERCALL_RELEASE);
```
:::{Note}
- The `ACQUIRE` hypercall generally mark the start and stop of a single execution.
- Reaching `RELEASE` generally means the execution is done with no errors.
- In the newer Nyx backend, reaching the `RELEASE` hypercall will automatically restore a guest snapshot.
:::

### `GET_PAYLOAD`

This hypercall is not actually getting the payload but instead telling Qemu
where to write the payload by providing it the payload's guest address.

Qemu will `mmap()` this buffer to make it shared with the fuzzer frontend.

:::{Warning}
- The guest must take care to allocate a sufficiently large buffer and make it page-aligned. 
- The guest must make sure the page is located in resident memory (no pagefaults required).
:::

::::{tab-set}
:::{tab-item} Linux
```{code-block} C
---
caption: Example
---
#include <unistd.h>
#include <stdlib.h>
#include <sys/mman.h>

// allocate page aligned 64KB buffer
long page_size = sysconf(_SC_PAGESIZE);
size_t buffer_size = 64 * 1024;
kAFL_payload *payload_buffer = aligned_alloc((size_t)page_size, buffer_size);
// ensure in resident memory
mlock(payload_buffer, buffer_size);
// ↔️ mmap shared buffer between QEMU and the fuzzer
kAFL_hypercall(HYPERCALL_KAFL_GET_PAYLOAD, (uintptr_t)payload_buffer);
```
:::
:::{tab-item} Windows
```{code-block} C
---
caption: Example
---
#include <windows.h>

// allocate page aligned 64KB buffer
// VirtualAlloc garantees a page aligned allocation
SIZE_T buffer_size = 64 * 1024;
kAFL_payload *payload_buffer  = VirtualAlloc(NULL, buffer_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
// ensure in resident memory
VirtualLock(payload_buffer, buffer_size);
// ↔️ mmap shared buffer between QEMU and the fuzzer
kAFL_hypercall(HYPERCALL_KAFL_GET_PAYLOAD, (uintptr_t)payload_buffer);
```
:::
::::


```{code-block} C
---
caption: kAFL_payload struct
---
typedef struct {
  int32_t size;
  uint8_t data[];
} kAFL_payload;
```

### `NEXT_PAYLOAD`

Triggers the actual write of the next payload into the previously registered buffer.

:::{Note}
In Nyx, the first invocation will also create a snapshot before writing the payload.
:::

This hypercall can be used in 2 different configurations, depending on the target support for fuzzing without restoring the snapshot, and how the user wants his harness to be implemented.

#### Fuzzing with snapshot restore

This is the most straightforward use case. No `while()` loop is required around the hypercall, since kAFL will take care of restoring the snapshot on each fuzzing iteration.

```{code-block} C
---
caption: Snapshot restore example
---
// 🔁 write next payload into the buffer
//    (take a snapshot on first call)
kAFL_hypercall(HYPERCALL_KAFL_NEXT_PAYLOAD, 0);
// 🟢 start coverage feedback collection
kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);
// ⚡ call fuzz target with the buffer
target_entry(payload_buffer->data, payload_buffer->size);
// ⚪ stop coverage feedback collection
kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
```

#### Fuzzing without snapshot restore

This is less common, but available nontheless to advanced users.

If the target can be fuzzed without snapshot restore (ie. it "survives" a fuzzing iteration) and if the user wants to gain some extra performance, the [`agent_non_reload_mode`](#set_agent_config) field can be set to disable snapshot mode.

The target will only be restored in case of timeouts or crashes.

```{code-block} C
---
caption: Snapshot restore disabled example
---
agent_config_t agent_config = {
    .agent_magic = NYX_AGENT_MAGIC,
    .agent_version = NYX_AGENT_VERSION,
    // Disable snapshot restore
    .agent_non_reload_mode = 1,
};
kAFL_hypercall(HYPERCALL_KAFL_SET_AGENT_CONFIG, (uintptr_t)&agent_config);
...
while (true) {
  // 🔁 write next payload into the buffer
  //    (take a snapshot on first call, execution loop will start here)
  kAFL_hypercall(HYPERCALL_KAFL_NEXT_PAYLOAD, 0);
  // 🟢 start coverage feedback collection
  kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);
  // ⚡ call fuzz target with the buffer
  target_entry(payload_buffer->data, payload_buffer->size);
  // ⚪ stop coverage feedback collection
  // target is not restored from the snapshot
  kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
}
```

:::{Note}
The fuzzer has an option [`-R`](./fuzzer_configuration.md#reload) that determines the number of persistent executions between full snapshot restore.

The default (`1`) is to always reload between each execution, but you can tweak this value with `10` or `100` persistent executions between reloads to gain more performance.

You can also set `0` for infinite execution.
:::

:::{warning}
Be careful since the target's state can be polluted between each iteration and bug reproducibility might become impossible.
:::

### `GET_HOST_CONFIG`

Used to query the host kAFL/QEMU configuration, for example to get the payload buffer size.

```{code-block} C
---
caption: Example
---
host_config_t host_config = {0};
kAFL_hypercall(HYPERCALL_KAFL_GET_HOST_CONFIG, (uintptr_t)&host_config);
hprintf("[host_config] payload size = %dKB\n", host_config.payload_buffer_size / 1024);
```

```{code-block} C
---
caption: host_config_t struct
---
typedef struct {
  // Safety check to be verified by the agent against his NYX_HOST_MAGIC value
  uint32_t host_magic;
  // Safety check to be verified by the agent against his NYX_AGENT_MAGIC value
  uint32_t host_version;
  // Size of the bitmap
  uint32_t bitmap_size;
  // TODO: not supported by the fuzzer frontend
  uint32_t ijon_bitmap_size;
  // Size of the payload buffer allocated by the host.
  // Agent payload buffer should be equal or larger than this value.
  uint32_t payload_buffer_size;
  // kAFL fuzzer worker ID
  uint32_t worker_id;
} host_config_t;
```

:::{Important}
This call is required as part of the kAFL initialization protocol.

Otherwise you will get this error:
`Guest ABORT: KVM_EXIT_KAFL_GET_HOST_CONFIG was not called`
:::

### `SET_AGENT_CONFIG`

Tells QEMU about capabilities of the agent harness and set custom tracing options.

```{code-block} C
---
caption: Example
---
agent_config_t agent_config = {
    .agent_magic = NYX_AGENT_MAGIC,
    .agent_version = NYX_AGENT_VERSION,
    // customize agent tracing options
    .agent_non_reload_mode = 1,
};
kAFL_hypercall(HYPERCALL_KAFL_SET_AGENT_CONFIG, (uintptr_t)&agent_config);
```

```{code-block} C
---
caption: agent_config_t struct
---
typedef struct {
  // TODO
  uint32_t agent_magic;
  // TODO
  uint32_t agent_version;
  // TODO
  uint8_t agent_timeout_detection;
  // The agent will perform the tracing. Disable host Intel-PT tracing.
  uint8_t agent_tracing;
  // TODO
  uint8_t agent_ijon_tracing;
  // Disable [`reload`](fuzzer_configuration.md#reload) mode
  uint8_t agent_non_reload_mode;
  // When using software instrumentation, define our own bitmap
  uint64_t trace_buffer_vaddr;
  // TODO
  uint64_t ijon_trace_buffer_vaddr;
  // TODO
  uint32_t coverage_bitmap_size;
  // TODO
  uint32_t input_buffer_size;
  // TODO
  uint8_t dump_payloads; /* set by hypervisor */
} agent_config_t;
```

:::{Important}
This call is required as part of the kAFL initialization protocol.

Otherwise you will get this error:
`Guest ABORT: KVM_EXIT_KAFL_SET_AGENT_CONFIG was not called`
:::

### `PANIC` / `KASAN`

They are used to raise a **crash** or other error event to the host.

QEMU will stop guest execution, reload the snapshot and report the crash type
to the frontend.

```{code-block} C
---
caption: Example
---
kAFL_hypercall(HYPERCALL_KAFL_PANIC, 0);
// or
kAFL_hypercall(HYPERCALL_KAFL_KASAN, 0);
```

### `SUBMIT_PANIC` / `SUBMIT_KASAN`

They tell QEMU the address of existing panic or sanitizer handler functions in the guest.
QEMU will overwrite the code at this address to perform `PANIC` / `KASAN` hypercalls so
that the events are detected and fuzz inputs can be logged on the host side.

```{code-block} C
---
caption: Example
---
panic_kebugcheck = resolve_KeBugCheck("KeBugCheck");
panic_kebugcheck2 = resolve_KeBugCheck("KeBugCheckEx");
kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_PANIC, panic_kebugcheck);
kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_PANIC, panic_kebugcheck2);
```

:::{Warning}
Rewrite can have unexpected results in case of inlined code or if the function is a macro.

It is often preferable and more flexible to manually place hypercalls in the corresponding error
and exception handlers with [`PANIC` and `KASAN`](#panic--kasan) hypercalls.

With this approach around 20-26 Bytes are overwritten, depending on whether the targets runs in protected or long mode.
See [nyx/hypercall/hypercall.h:Panic and KASAN notifier payloads](https://github.com/IntelLabs/kafl.qemu/blob/61cb6cc5b45b5fc9ececf37737a1b88d787fb187/nyx/hypercall/hypercall.h#L42)

```{code-block} C
---
caption: Example - Panic Notifier Payload (x86-64)
---
/*
 * Panic Notifier Payload (x86-64)
 * fa                      cli
 * 48 c7 c0 1f 00 00 00    mov    rax,0x1f
 * 48 c7 c3 08 00 00 00    mov    rbx,0x8
 * 48 c7 c1 00 00 00 00    mov    rcx,0x0
 * 0f 01 c1                vmcall
 * f4                      hlt
 */
#define PANIC_PAYLOAD_64                                                           \
    "\xFA\x48\xC7\xC0\x1F\x00\x00\x00\x48\xC7\xC3\x08\x00\x00\x00\x48\xC7\xC1\x00" \
    "\x00\x00\x00\x0F\x01\xC1\xF4"
```
:::

## Further optional hypercalls

### `PRINTF`

Sends a pointer to a C string to the host, where it will be printed or logged.

Very useful for general logging/debug, forwarding sanitizer reports and exception stack dumps.

```{code-block} C
---
caption: Example
---
kAFL_hypercall(HYPERCALL_KAFL_PRINTF, "kAFL fuzzer initialized.");
```

:::{Warning}
This hypercall should be used as a debug utility for agent "debug" builds.

Once the fuzzer is started, having hprintfs in the loop will **significantly** impact the performance.
:::

:::{Note}
Instead of using this hypercall directly, the API proposes a wrapper utility functions: [`hprintf()`](#hprintf),
which provides variadic arguments and string formatting.
:::

### `RANGE_SUBMIT`

Used to configure the IP filter range for PT tracing.

This is useful when code ranges are not known at startup time or simply easier to
obtain as part of agent initialization.

```{code-block} C
---
caption: Example
---
uint64_t buffer[3] = {0};
buffer[0] = 0xfffff8010e0b0000 // low range
buffer[1] = 0xfffff8010e0b7000 // high range
buffer[2] = 0; // IP filter index [0-3]
kAFL_hypercall(HYPERCALL_KAFL_RANGE_SUBMIT, (uint64_t)buffer);
```

:::{Note}
Overrides the corresponding [`-ipN`](../reference/fuzzer_configuration.md#ip0-1-2-3) setting by fuzzer frontend.
:::

### `SUBMIT_CR3`

Tells QEMU to use the currently configured `CR3` value as a filter
for PT tracing. Useful to limit trace to a specific task/context.

```{code-block} C
---
caption: Example
---
kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_CR3, 0);
```

:::{Note}
- Running the fuzzer without an enabled CR3 filter is actually not supported if Intel PT mode is enabled and also by the actual decoding library libxdc.
- This hypercall must be called at least once before [`HYPERCALL_KAFL_ACQUIRE`](#acquire--release)
- If snapshots are enabled, it is, in most cases, sufficient to call `HYPERCALL_KAFL_SUBMIT_CR3` once before [`HYPERCALL_KAFL_NEXT_PAYLOAD`](#next_payload)
- If snapshots are disabled, but the agent keeps running in the same process, it is also sufficient to call this hypercall once
- For userland fuzzing in non-snapshot mode, however, it might be necessary to call `HYPERCALL_KAFL_SUBMIT_CR3` with each execution after [`HYPERCALL_KAFL_NEXT_PAYLOAD`](#next_payload) but before [`HYPERCALL_KAFL_ACQUIRE`](#acquire--release) to ensure that the current CR3 value is passed to the hypervisor. This is especially true if, in non-snapshot mode, a fork server is being used.
:::

### `USER_ABORT`

Signals a fatal error to QEMU.

Mainly useful as a kind of `assert()` from harness perspective (since we auto-resume on regular crash/hang).

```C
kAFL_hypercall(HYPERCALL_KAFL_USER_ABORT, "Host payload size too large!");
```

### `USER_SUBMIT_MODE`

Explicitly tells the host if the target is 32 or 64 bit code.

Influences QEMU code rewrite and possibly libxdc decoder. Typically auto-detected.

```C
// submit 64 bits mode
kAFL_hypercall(HYPERCALL_KAFL_USER_SUBMIT_MODE, KAFL_MODE_64);
```

### `USER_RANGE_ADVISE`

Advise the guest of the IP filters settings in the fuzzer configuration.

```{code-block} C
---
caption: kAFL_ranges struct
---
typedef struct {
  uint64_t ip[4];
  uint64_t size[4];
  uint8_t enabled[4];
} kAFL_ranges; 
```

```{code-block} C
---
caption: Example
---
#include <inttypes.h>
#define INTEL_PT_MAX_RANGES 4

kAFL_ranges ranges = {0};
kAFL_hypercall(HYPERCALL_KAFL_USER_RANGE_ADVISE, (uint64_t)&ranges);
for (int i = 0; i < INTEL_PT_MAX_RANGES; i++) {
  printf("IP filter index: %" PRId64 "\n", ranges.ip[i]);
  printf("IP range size: %" PRIx64 "\n", ranges.size[i]); // high - low
  printf("IP range enabled: %" PRId8 "\n", ranges.enabled[i]);
}
```

:::{Note}
In the case of userland fuzzing, the agent is supposed to make the corresponding code ranges persistent (and prefetched) in the guest's memory by calling `mlock()` so that the hypervisor has a chance to dump the required pages for the PT decoder.

However, this step is most likely no longer required since code pages can now be dumped even if they are not yet present in the guest's memory at the time of creating the snapshot (for that, we are using hardware breakpoints and some other hacks).

Nevertheless, it might be reasonable to prefetch the code pages for better fuzzing performance.
:::

### `REQ_STREAM_DATA`

Fetches a named binary buffer from the host. QEMU fetches
the data from correspondingly named files in the `sharedir` folder.

Assuming a file exists
```{code-block} shell
---
caption: Host sharedir content
---
echo "Hello kAFL !" > sharedir/example.txt
```

```{code-block} shell
---
caption: Example
---
#define SHAREDIR_FILENAME "example.txt"

uint8_t buffer[0x1000] = {0};
strncpy(buffer, SHAREDIR_FILENAME, strlen(SHAREDIR_FILENAME) - 1);
kAFL_hypercall(HYPERCALL_KAFL_REQ_STREAM_DATA, (uint64_t)buffer);
printf("%s\n", buffer); // prints "Hello kAFL !"
```

### `DUMP_FILE`

Can be used to send binary buffers that will be stored as files in `$WORK_DIR/dump/`.

Supply `NULL` or a valid `mkstemp()` template as filename to let QEMU create a unique filename for you.

```{code-block} C
---
caption: kafl_dump_file_t struct
---
typedef struct {
  uint64_t file_name_str_ptr; // desired filename
  uint64_t data_ptr; // buffer to be dumped
  uint64_t bytes; // size of the buffer
  uint8_t append; // whether to append to an existing file or not
} kafl_dump_file_t
```

```{code-block} C
---
caption: Example
---
FILE* f = fopen("/proc/kallsyms", "rb");
char buffer[4096];
fread(buffer, 1, 4095, f);
buffer[4095] = '\0';
kafl_dump_file_t dump_file = {
  .file_name_str_ptr = NULL,
  .data_ptr = buffer,
  .bytes = 4096,
  .append = 0
};
kAFL_hypercall(HYPERCALL_KAFL_DUMP_FILE, (uint64_t)buffer);
```

### `USER_FAST_ACQUIRE`

A combination of `NEXT_PAYLOAD`, `SUBMIT_CR3` and `ACQUIRE`.

Mainly exists to save you a VM exit.

Only tested for usermode fuzzing.

```{code-block} C
---
caption: Example
---
kAFL_hypercall(HYPERCALL_KAFL_USER_FAST_ACQUIRE, 0);
// ⚡ call fuzz target with the buffer
target_entry(payload_buffer->data, payload_buffer->size);
// ⚪ stop coverage feedback collection
kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
```

:::{Note}
This hypercall basically solves the issue of changing CR3 values in case of disabled snapshots and an in-guest employed fork server without requiring to call 3 different snapshots in a row.
:::

### `LOCK`

Generates a VM pre-snapshot for the fuzzer and subsequently terminates QEMU, if QEMU is configured correctly.

This is useful when the target program needs to be brought into a complex state before the fuzzing can begin.

Also useful to skip long boot times and restore the VM when the target is about to be executed.

```{code-block} C
---
caption: Example
---
// will take a snapshot and terminate QEMU
kAFL_hypercall(HYPERCALL_KAFL_LOCK, 0);
// fuzzer will restore the VM from here
// kAFL initialization can begin
// 🤝 handshake 
kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);
kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
// ...
```

:::{Note}
For more documentation on QEMU-Nyx pre-snapshot and QEMU configuration, see [Nyx VMs](https://github.com/nyx-fuzz/Nyx/blob/main/docs/01-Nyx-VMs.md)
:::

:::{Warning}
In case QEMU-Nyx is started without enabling the pre-snapshot capability, this hypercall will effectively do nothing.
:::

### `REQ_STREAM_DATA_BULK`

This hypercall serves basically the same purpose as REQ_STREAM_DATA, but can be used to achieve much better transfer speeds for larger files due to bulk operations instead of fetching only 4KB per executed hypercall.

```{code-block} C
---
caption: kafl_dump_file_t struct
---
typedef struct {
  char file_name[256];  // requested sharedir filename
  uint64_t num_addresses; // addresses array count. must be <= 479
  uint64_t addresses[479]; // 
} req_data_bulk_t;
```

:::{Note}
this hypercall might only be as fast or even slightly slower for smaller files (`<= 1MB`) than [`REQ_STREAM_DATA`](#req_stream_data).
:::

### `PERSIST_PAGE_PAST_SNAPSHOT`

This hypercall excludes a single page frame from being reset by the snapshot restore mechanism.

```{code-block} C
---
caption: Example
---
uint64_t pfn = 0x8048000;
kAFL_hypercall(HYPERCALL_KAFL_PERSIST_PAGE_PAST_SNAPSHOT, pfn);
```

:::{Note}
This hypercall expects a page-aligned virtual address of a single page at a time (but can be called multiple times to exclude a number of page frames from being reset).
:::

## Utility functions

A set of additional utility functions have been built on top of kAFL hypercalls and made available in the [`nyx_api.h`](https://github.com/IntelLabs/kafl.targets/blob/master/nyx_api.h)
for convenience.

### `habort`

```{code-block} C
---
caption: Definition
---
static void habort(char* msg);
```

Convenience function to abort execution.

```{code-block} C
---
caption: Example
---
habort("Host payload size too large!");
```

### `hprintf`

```{code-block} C
---
caption: Definition
---
static void hprintf(const char * format, ...);
```

This function is the equivalent of [`printf`](https://cplusplus.com/reference/cstdio/printf/), accepting with variadic arguments, but using the [`KAFL_HYPERCALL_PRINTF`](#printf) as printing backend.

```{code-block} C
---
caption: Example
---
hprintf("kAFL: Address of payload buffer %lp...\n", payload_buffer);
```

## Untested and not fully integrated

- `PANIC_EXTENDED` – a mix of PANIC and HPRINTF, raises a bug while also
  forwarding a pointer to a C string. Untested.

- `CREATE_TMP_SNAPSHOT` – create an incremental snapshot and continue fuzzing
  from current position. Frontend and harness have to support this.

- `DEBUG_TMP_SNAPSHOT` – debug version of incremental snapshot

- `NESTED_*` - roughly equivalent hypercalls for use with nested virtualization
  (when agent is a L2 guest)

## Deprecated

- `GET_PROGRAM` / `GET_ARGV`: was using to send a host target into the guest to be executed. Replaced by the more flexible kAFL `sharedir` feature.
- `INFO`: was used to dump and push guest information to the host. Replaced by [`PRINTF`](#printf).
- `PRINTK_ADDR` / `PRINTK`: submit the pointer of a `printk()`-like logging function. Qemu will rewrite this with a `PRINTK` hypercall which can interpret `printk()` args.
- `TIMEOUT`: TODO
