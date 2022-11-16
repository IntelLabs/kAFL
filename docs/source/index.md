📗 kAFL's Documentation
====================

_kAFL_/_Nyx_ is a fast guided fuzzer for the x86 VM. It is great for anything that
executes as _QEMU_/_KVM_ guest, in particular x86 firmware, kernels and full-blown
operating systems.

## Features

- _kAFL_/_Nyx_ uses [_Intel VT_](https://www.intel.com/content/www/us/en/virtualization/virtualization-technology/intel-virtualization-technology.html), [_Intel PML_](https://www.intel.com/content/dam/www/public/us/en/documents/white-papers/page-modification-logging-vmm-white-paper.pdf) and _Intel PT_ to achieve efficient execution, snapshot reset and coverage feedback for greybox or whitebox fuzzing scenarios. It allows to run many x86 FW and OS kernels with any desired toolchain and minimal code 
modifications.

- The kAFL-Fuzzer is written in Python and designed for parallel fuzzing with multiple Qemu instances. kAFL follows an AFL-like design but is easy to extend with custom mutation, analysis or scheduling options.

- kAFL integrates the [_Radamsa_](https://gitlab.com/akihe/radamsa) fuzzer as well as [_Redqueen_](https://github.com/RUB-SysSec/redqueen) and [_Grimoire_](https://github.com/RUB-SysSec/grimoire) extensions. Redqueen uses VM introspection to extract runtime inputs to conditional instructions, overcoming typical magic byte and other input checks. Grimoire attempts to identify keywords and syntax from fuzz inputs in order to generate more clever large-scale mutations.

For details on Redqueen, Grimoire, [_IJON_](https://github.com/RUB-SysSec/ijon), Nyx, please visit [nyx-fuzz.com](https://nyx-fuzz.com).

## Components

The project is structured around multiple components:

- [`IntelLabs/kAFL`](https://github.com/IntelLabs/kAFL): The main repository which organises all subcomponents
- [`IntelLabs/kafl.fuzzer`](https://github.com/IntelLabs/kafl.fuzzer): The fuzzer frontend
- [`IntelLabs/kafl.linux`](https://github.com/IntelLabs/kafl.linux): Modified KVM with Intel PT and kAFL hypercalls support
- [`IntelLabs/kafl.qemu`](https://github.com/IntelLabs/kafl.qemu): Modified QEMU with fast-snapshots support
- [`IntelLabs/kafl.libxdc`](https://github.com/IntelLabs/kafl.libxdc): Fast Intel PT decoding library
- [`IntelLabs/kafl.targets`](https://github.com/IntelLabs/kafl.targets): Example kAFL targets

## Contents

```{toctree}
:maxdepth: 2
:caption: Tutorials

tutorials/introduction
tutorials/installation
tutorials/fuzzing_linux_kernel
```

```{toctree}
:maxdepth: 2
:caption: Reference

reference/deployment
reference/hypercall_api
```
