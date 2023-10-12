# Concepts

Before we dive into a specific target, we need to introduce the concept of a _kAFL Agent_ that will used at the next step of the tutorial

We assume you are already familiar with fuzzing vocabulary ([Google's fuzzing glossary](https://github.com/google/fuzzing/blob/master/docs/glossary.md) can be helpful here).

## kAFL Agent

The term _kAFL Agent_ simply refers to the implementation of a fuzzing harness in the guest.

The _Agent_ is responsible for both instrumenting and overseeing a specific portion of the SUT (_System Under Test_) through a set of [hypercalls](../reference/hypercall_api.md).

Considering that these hypercalls constitues a communication channel with the external virtual machine environment, the term _agent_ has been employed, akin to a guest agent.

```{mermaid}
graph LR
    fuzzer["kAFL Fuzzer"] <--> QEMU["QEMU/KVM"]
    subgraph Virtual Machine
        Agent["kAFL Agent"] <-- Instruments --> SUT["Software Under Test"]
    end
    QEMU <-- Hypercalls --> Agent
```

```{code-block} C
---
caption: Example of a simplified kAFL Agent fuzzing a target function called `target()`
---
// 🤝 kAFL handshake 
kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);
kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
// allocate kAFL payload buffer
kAFL_payload *payload_buffer = malloc(PAYLOAD_SIZE);
// kAFL configuration, filters, etc...
// 🟢 Enable feedback collection
kAFL_hypercall(KAFL_HYPERCALL_ACQUIRE);
// ⚡call target func ...
target(payload_buffer->data, payload_buffer->size);
// ⚪ Disable feedback collection
kAFL_hypercall(KAFL_HYPERCALL_RELEASE);
```

## Pick a Target !

Now you are ready to configure one of our pre-baked kAFL targets, and start the fuzzer !

- ➡️ Continue by [fuzzing Linux targets](././linux/index.md)
- ➡️ Continue by [fuzzing Windows programs](./windows/index.md)
