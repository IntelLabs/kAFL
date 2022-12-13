<h1 align="center">
  <br>kAFL</br>
</h1>

<h3 align="center">
HW-assisted Feedback Fuzzer for x86 VMs
</h3>

<p align="center">
  <a href="https://github.com/IntelLabs/kAFL/actions/workflows/CI.yml">
    <img src="https://github.com/IntelLabs/kAFL/actions/workflows/CI.yml/badge.svg" alt="CI">
  </a>
</p>
<p align="center">
  <a href="https://IntelLabs.github.io/kAFL/">
    <img src="https://img.shields.io/badge/Online-Documentation-green?style=for-the-badge&logo=gitbook" alt="online_docs"/>
  </a>
</p>

kAFL/Nyx is a fast guided fuzzer for the x86 VM. It is great for anything that
executes as QEMU/KVM guest, in particular x86 firmware, kernels and full-blown
operating systems.

**Note: All components are provided for research and validation purposes only.
Use at your own Risk**


## Features

- kAFL/Nyx uses [_Intel VT_](https://www.intel.com/content/www/us/en/virtualization/virtualization-technology/intel-virtualization-technology.html), [_Intel PML_](https://www.intel.com/content/dam/www/public/us/en/documents/white-papers/page-modification-logging-vmm-white-paper.pdf) and _Intel PT_ to achieve efficient execution, snapshot reset and coverage feedback for greybox or whitebox fuzzing scenarios. It allows to run many x86 FW and OS kernels with any desired toolchain and minimal code 
modifications.

- kAFL uses a custom [kAFL-Fuzzer](https://github.com/IntelLabs/kafl.fuzzer)
  written in Python. The kAFL-Fuzzer follows an AFL-like design and is optimized
  for working with many Qemu instances in parallel, supporting flexible VM
  configuration, logging and debug options.

- kAFL integrates the [_Radamsa_](https://gitlab.com/akihe/radamsa) fuzzer as well as [_Redqueen_](https://github.com/RUB-SysSec/redqueen) and [_Grimoire_](https://github.com/RUB-SysSec/grimoire) extensions. Redqueen uses VM introspection to extract runtime inputs to conditional instructions, overcoming typical magic byte and other input checks. Grimoire attempts to identify keywords and syntax from fuzz inputs in order to generate more clever large-scale mutations.

For details on Redqueen, Grimoire, [_IJON_](https://github.com/RUB-SysSec/ijon), Nyx, please visit [nyx-fuzz.com](https://nyx-fuzz.com).

## Getting Started

➡️ The official [tutorial](https://IntelLabs.github.io/kAFL/tutorials/introduction.html) will walk you through your first steps
to setup kAFL and fuzz the Linux kernel !

_Note: kAFL requires a Gen-6 Skylake CPU, or newer._
