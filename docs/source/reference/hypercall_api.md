# kAFL/Nyx Hypercall API

For fuzzing in kAFL/Nyx, the guest VM issues special hypercalls to bootstrap and
coordinate the execution of the fuzzing harness with the fuzzer frontend.

This approach offers a minimal low-level interface that can be used to take
control and start injecting inputs at any point in VM guest execution.


## Essential hypercalls

- `ACQUIRE / RELEASE` are used to enable/disable feedback collection and
  generally mark the start and stop of a single execution. One initial set of
  `ACQUIRE`/`RELEASE` hypercalls is also used for initial handshake with the host
  frontend. Reaching `RELEASE` generally means the execution is done with no
  errors (return OK). The newer Nyx backend will automatically restore a guest
  snapshot on RELEASE hypercall.

- `GET_PAYLOAD` is not actually getting the payload but instead telling Qemu
  where to write the payload. The guest must take care to allocate a
  sufficiently large buffer and make it page-aligned. Qemu will mmap() this
  buffer to make it shared with the fuzzer frontend.

- `NEXT_PAYLOAD` triggers the actual write of the next payload into the
  previously registered buffer. In Nyx, the first invocation will also create
  a snapshot before writing the payload, so our fuzzing “loop” actually always
  starts from this hypercall now. The `while()` loop in our guest agent is not
  actually needed anymore.

- `PRINTF` send a pointer to a C string to the host, where it will be printed or
  logged. Very useful for general logging/debug, forwarding sanitizer reports
  and exception stack dumps.

- `PANIC`, `KASAN` are used to raise a ‘crash’ or other error event to the host.
  Qemu will stop Guest execution, reload the snapshot and report the crash type
  to the frontend.

- `SUBMIT_PANIC`, `SUBMIT_KASAN` tell Qemu the address of existing panic or
  sanitizer handler functions in the guest. Qemu will overwrite the code at this
  address to perform `PANIC`/`KASAN` hypercalls so that the events are detected
  and fuzz inputs can be logged on the host side.  Rewrite can have unexpected
  results in case of inlined code or if the function is a macro etc. It is often
  preferable and more flexible to manually place hypercalls in the corresponding
  error and exception handlers.


## Further optional hypercalls

- `RANGE_SUBMIT` is used to configure the IP filter range for PT tracing. This
  is useful when code ranges are not known at startup time or simply easier to
  obtain as part of agent initialization. Overrides the corresponding `-ipN`
  setting by fuzzer frontend.

- `SUBMIT_CR3` tells Qemu to use the currently configured CR3 value as a filter
  for PT tracing. Useful to limit trace to a specific task/context.

- `USER_ABORT` signals a fatal error to Qemu. Mainly useful as a kind of
  assert() from harness perspective (since we auto-resume on regular crash/hang).

- `USER_SUBMIT_MODE` explicitly tells the host if the target is 32 or 64 bit code.
  Influences Qemu code rewrite and possibly libxdc decoder. Typically auto-detected.

- `SET_AGENT_CONFIG` tells Qemu about capabilities of the harness (agent), e.g.
  custom tracing options. Further options may be added by extending the handler on Qemu side.

- `GET_HOST_CONFIG` can be used to query kAFL/Qemu configuration, e.g. size of the payload buffer.

- `REQ_STREAM_DATA` fetches a named binary buffer from the host. Qemu fetches
  the data from correspondingly named files in the [sharedir folder](sharedir_tutorial.md)

- `DUMP_FILE` can be used to send binary buffers that will be stored as files in
  $WORK_DIR/dump/. Supply NULL or a valid mkstemp() template as filename to
  let Qemu create a unique filename for you.

- `USER_FAST_ACQUIRE` this is a combination of `NEXT_PAYLOAD` and `ACQUIRE` and
  mainly exists to save you a VM exit. Only tested for usermode fuzzing.


## Untested and not fully integrated

- `PRINTK_ADDR` – submit the pointer of a printk()-like logging function. Qemu
  will rewrite this with a `PRINTK` hypercall which can interpret printk() args.

- `PANIC_EXTENDED` – a mix of PANIC and HPRINTF, raises a bug while also
  forwarding a pointer to a C string. Untested.

- `CREATE_TMP_SNAPSHOT` – create an incremental snapshot and continue fuzzing
  from current position. Frontend and harness have to support this.

- `DEBUG_TMP_SNAPSHOT` – debug version of incremental snapshot

- `NESTED_*` - roughly equivalent hypercalls for use with nested virtualization
  (when agent is a L2 guest)

- `USER_RANGE_ADVISE`, `GET_ARGV` – no idea

- `INFO`, `LOCK`, `GET_PROGRAM` – deprecated
