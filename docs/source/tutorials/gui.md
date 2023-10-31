➡️ You can start the [kAFL GUI](../../../reference/user_interface.md) to watch the campaign progress live in your terminal

Among all the indicators, take a closer look at the `Progress` panel, and especially the `Findings` column.

You should see 4 fields:

- `Crash`: Executions returning with PANIC or PANIC_EXTENDED hypercall
- `AddSan`: Executions returning with KASAN hypercall
- `Timeout`: Executions intercepted by QEMU timeout
- `Regular`: Executions returning with RELEASE hypercall
