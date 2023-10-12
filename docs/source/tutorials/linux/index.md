# Linux Target

This section features 2 targets:

- Damn Vulnerable Kernel Module (DVKM)
- Linux kernel boot sequence fuzzing

Too get started with kAFL, we recommend following the [DVKM](./dvkm/index.md) tutorial.
This tutorial offers step-by-step explanations and covers foundational concepts for beginnners.

:::{note}
The Linux kernel serves as an excellent candidate for fuzzing with kAFL for two key reasons:

1. Access to source code: inserting hypercalls at critical kernel locations is straightforward
2. Sanitizers available: the kernel can be compiled with ([`KASAN`](https://www.kernel.org/doc/html/v4.14/dev-tools/kasan.html)), significantly aiding in the identification of crash locations and faulty lines of code.
:::

```{toctree}
:maxdepth: 2
:caption: Fuzzing on Linux

dvkm/index
fuzzing_linux_kernel
```
