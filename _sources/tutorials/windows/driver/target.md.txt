# Target analysis

## Objectives

The objective of this tutorial is to fuzz a Windows driver, built for educational purposes.

It doesn't interact with any hardware device, nor makes any relevant side effect in the kernel.

It simply receives and processes IOCTLs, by calling a handler function which contains vulnerabilities that we want to trigger.

## Source code

The source code for this driver is located at the [`kafl.targets/windows_x86_64/src`](https://github.com/IntelLabs/kafl.targets/tree/master/windows_x86_64/src).

It is composed of:

- [`driver.c`](https://github.com/IntelLabs/kafl.targets/blob/master/windows_x86_64/src/kafl_vulnerable_driver/driver.c): the vulnerable driver
- [`vuln_test.c`](https://github.com/IntelLabs/kafl.targets/blob/master/windows_x86_64/src/driver/vuln_test.c): a userland application to trigger the driver

This is a representation of what the code does at the core, excluding kAFL hypercalls:

```{mermaid}
graph TD
    subgraph Userspace
        createfile["CreateFile('\\Device\\testKafl')"] --> ioctl["DeviceIoControl(IOCTL_KAFL_INPUT)"]
    end
    subgraph Driver
        ioctl --> handleirp["handleIrp()"]
        handleirp -->|"IOCTL_KAFL_INPUT"| crashme["crashMe()"]
    end
```

## Vulnerability

Two security flaws have been inserted into the driver code

More specifically they are [NULL pointer dereference](https://cwe.mitre.org/data/definitions/476.html#:~:text=A%20NULL%20pointer%20dereference%20occurs,causing%20a%20crash%20or%20exit.) vulnerabilities, triggered by the `crashMe()` function when a certain buffer is received.

```c
NTSTATUS crashMe(IN PIO_STACK_LOCATION IrpStack){
    SIZE_T size = 0;
    PCHAR userBuffer = NULL;

    userBuffer = IrpStack->Parameters.DeviceIoControl.Type3InputBuffer;
    size = IrpStack->Parameters.DeviceIoControl.InputBufferLength;

    if (size < 0xe){
        return STATUS_SUCCESS;
    }

    if (userBuffer[0] == 'P'){
        DbgPrint("[+] KAFL vuln drv -- P");
        if (userBuffer[1] == 'w'){
            DbgPrint("[+] KAFL vuln drv -- Pw");
            if (userBuffer[2] == 'n'){
                DbgPrint("[+] KAFL vuln drv -- Pwn");
                if (userBuffer[3] == 'T'){
                    DbgPrint("[+] KAFL vuln drv -- PwnT");
                    if (userBuffer[4] == 'o'){
                        DbgPrint("[+] KAFL vuln drv -- PwnTo");
                        if (userBuffer[5] == 'w'){
                            DbgPrint("[+] KAFL vuln drv -- PwnTow");
                            if (userBuffer[6] == 'n'){
                                DbgPrint("[+] KAFL vuln drv -- PwnTown: CRASH");
                                ((VOID(*)())0x0)();
                            }
                        }
                    }
                }
            }
        }
    }

    if (userBuffer[0] == 'w'){
        DbgPrint("[+] KAFL vuln drv -- w");
        if (userBuffer[1] == '0'){
            DbgPrint("[+] KAFL vuln drv -- w0");
            if (userBuffer[2] == '0'){
                DbgPrint("[+] KAFL vuln drv -- w00");
                if (userBuffer[3] == 't'){
                    DbgPrint("[+] KAFL vuln drv -- w00t: CRASH");
                    size = *((PSIZE_T)(0x0));
                }
            }
        }
    }

    return STATUS_SUCCESS;
}
```

We can recognize 2 paths leading to a crash:
```{mermaid}
graph TD
    classDef red fill:#ff7d7d
    subgraph Driver
        crashme -->|"PwnTown"| null["NULL pointer dereference"]:::red
        crashme -->|"w00t"| null
    end
```

:::{Note}
This is a good example to showcase kAFL's RedQueen builtin capabilities.

For the fuzzer to progress quickly through these conditionals, it uses a combination of virtual machine introspection and instruction comparison,
which is the core of RedQueen's implementation.
:::

## kAFL agent implementation

Let's now have a deeper look at the kAFL agent implementation, to better understand what specific changes this target required.

First , the kAFL agent is only implemented in the userland component `vuln_test.c`, for 2 reasons:

- the driver implementation remains untouched: there is no requirement to change the driver logic in order to add our harness
- at the time of this writing, kAFL hypercall implementation based on `vmcall` instruction doesn't get along very well with Microsoft's `MSVC` compiler

### Agent initialization

We can find in `init_agent_handshake()` the common agent initialization sequence:

```{mermaid}
stateDiagram-v2
    state "HYPERCALL_KAFL_ACQUIRE
    HYPERCALL_KAFL_RELEASE" as handshake
    state "HYPERCALL_KAFL_SUBMIT_CR3" as cr3
    state "HYPERCALL_KAFL_USER_SUBMIT_MODE" as mode
    state "HYPERCALL_KAFL_GET_HOST_CONFIG" as host_config
    state "HYPERCALL_KAFL_SET_AGENT_CONFIG" as agent_config

    note right of handshake
        kAFL "Handshake" 🤝
    end note
    note left of cr3
        submit current process CR3
    end note
    note right of mode
        submit 64 bits mode
    end note
    note left of host_config
        request host's fuzzer configuration
        check API mismatch
        check buffer size
    end note
    note right of agent_config
        configure our agent
        ⚠️ set agent_non_reload_mode to allow persistent execution
    end note
    handshake --> cr3
    cr3 --> mode
    mode --> host_config
    host_config --> agent_config
```

### Fuzzing harness

The fuzzing harness is implemented around `DeviceIoControl()`

Harness sequence diagram between kAFL fuzzer, userspace and driver:
```{mermaid}
sequenceDiagram
    participant D as Driver
    participant U as Userspace
    participant K as kAFL

    rect rgb(232, 235, 237)
        loop payload execution
            U->>K: HYPERCALL_KAFL_NEXT_PAYLOAD
            Note over K,U: Write next payload in buffer
            U->>K: HYPERCALL_KAFL_ACQUIRE
            Note over K,U: Start coverage tracing
            U->>D: DeviceIoControl()
            Note over U,D: Submit payload buffer with IOCTL
            alt crash
                D->>K: HYPERCALL_KAFL_PANIC
                Note over D,K: (kernel) Submit crash event with KeBugCheck rewritten handler
            else non-crashing
                U->>K: HYPERCALL_KAFL_RELEASE
                Note over K,U: End coverage tracing
            end
        end
    end
```

```{code-block} C
---
caption: Harness implementation
---
// Snapshot here
// request new payload (*blocking*)
kAFL_hypercall(HYPERCALL_KAFL_NEXT_PAYLOAD, 0);

// Enable coverage tracing
kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0); 

// kernel fuzzing
DeviceIoControl(kafl_vuln_handle,
    IOCTL_KAFL_INPUT,
    (LPVOID)(payload_buffer->data),
    (DWORD)payload_buffer->size,
    NULL,
    0,
    NULL,
    NULL
);

// inform fuzzer about finished fuzzing iteration
// Will reset back to start of snapshot here
kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
```


### Target specific

#### Panic handlers

If we want kAFL to be aware of a crash on Windows, we need to intercept and hook the crash handlers.

The Windows functions we need are:
- [`KeBugCheck`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kebugcheckex)
- [`KeBugCheckEx`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-kebugcheck)

Therefore we have to:
1. locate the address of these functions in the kernel
2. submit them to kAFL so that QEMU can rewrite these functions with kAFL hypercalls

The first step is performed by `resolve_KeBugCheck()`

1. [`EnumDeviceDrivers()`](https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-enumdevicedrivers) to retrieve the load address of each driver in the system
2. [`GetDeviceDriverFileName()`](https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-getdevicedriverfilenamea) to retrieve path available for the specified driver
3. if the entry is `ntoskrnl.exe`, use [`LoadLibrary()`](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya) and [`GetProcAddress()`](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress) to retrieve the address of `KeBugCheck`

Once this is done, the address is simply sent to kAFL via [`HYPERCALL_KAFL_SUBMIT_PANIC`](https://intellabs.github.io/kAFL/reference/hypercall_api.html#panic-kasan).

#### Set IP ranges

IP ranges are necessary to run the fuzzer in guided feedback mode.

To retrieve the start and end IP range of our `kAFLvulnerabledriver.sys` loaded driver, we need to do the following:

1. [`EnumDeviceDrivers()`](https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-enumdevicedrivers) to retrieve the load address of each driver in the system
2. [`NtQuerySystemInformation`](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation) with `SystemObjectInformation` to retrieve module information about each driver
3. identify our driver
4. [`HYPERCALL_KAFL_RANGE_SUBMIT`](https://intellabs.github.io/kAFL/reference/hypercall_api.html#range-submit) to submit the IP ranges to kAFL

#### Non reload mode

During the agent configuration, we configured the [`agent_non_reload_mode`](https://intellabs.github.io/kAFL/reference/hypercall_api.html#set-agent-config).

We prevent the host from reloading the guest snapshot on each new payload execution.

Why are we doing this ? Snapshot fuzzers are well suited for complex targets with a lot of side effects.

We are lucky because this isn't our situation: the driver simply doesn't have any side effect (it doesn't allocate memory on each payload execution, no hardware communication, etc ...)

So we can improve the fuzzing speed by ditching the snapshot reload and keeping the guest running in a persistent state.
