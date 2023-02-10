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
  <a href="https://github.com/IntelLabs/kAFL/releases">
    <img alt="GitHub release (latest by date)" src="https://img.shields.io/github/v/release/IntelLabs/kAFL">
  </a>
  <a href="https://hub.docker.com/r/intellabs/kafl">
    <img alt="Docker Image Version (latest by date)" src="https://img.shields.io/docker/v/intellabs/kafl?label=Docker%20Image">
  </a>
  <a href="https://hub.docker.com/r/intellabs/kafl">
    <img alt="Docker Pulls" src="https://img.shields.io/docker/pulls/intellabs/kafl">
  </a>
  <a href="https://github.com/IntelLabs/kAFL/blob/master/LICENSE.md">
    <img alt="GitHub" src="https://img.shields.io/github/license/IntelLabs/kafl">
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


## Requirements

- **Intel Skylake or later:** The setup requires a Gen-6 or newer Intel CPU (for
  Intel PT) and adequate system memory (~2GB RAM per CPU)

- **Patched Host Kernel:** A modified Linux host kernel will be installed as part
  of the setup. Running kAFL inside a VM may work starting IceLake or later CPU.

- **Recent Debian/Ubuntu:** The installation and tutorials are
  tested for recent Ubuntu LTS (>=20.04) and Debian (>=bullseye).


## Getting Started

Once you have python3-venv and make installed, you can install kAFL using `make deploy`:

```
sudo apt install python3-venv make git
git clone https://github.com/IntelLabs/kAFL.git
cd kAFL; make deploy
```

Installation make take some time and require a reboot to update your kernel.

Check the detailed [installation guide](https://intellabs.github.io/kAFL/tutorials/installation.html) in case
of trouble, or the [deployment guide](https://intellabs.github.io/kAFL/reference/deployment.html) for detailed
information and customizing the kAFL setup for your project.

As a first fuzzing example, we recommend [Fuzzing the Linux Kernel](https://intellabs.github.io/kAFL/tutorials/fuzzing_linux_kernel.html).


