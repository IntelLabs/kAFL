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

kAFL/Nyx is a fast guided fuzzer for the x86 VM. It is great for anything that
executes as Qemu/KVM guest, in particular x86 firmware, kernels and full-blown
operating systems.

**Note: All components are provided for research and validation purposes only.**

## Features

- kAFL/Nyx uses Intel VT, Intel PML and Intel PT to achieve efficient execution,
  snapshot reset and coverage feedback for greybox or whitebox fuzzing scenarios.
  It allows to run many x86 FW and OS kernels with any desired toolchain and
  minimal code modifications.

- The kAFL-Fuzzer is written in Python and designed for parallel fuzzing with
  multiple Qemu instances. kAFL follows an AFL-like design but is easy to
  extend with custom mutation, analysis or scheduling options.

- kAFL integrates the Radamsa fuzzer as well as Redqueen and Grimoire extensions.
  Redqueen uses VM introspection to extract runtime inputs to conditional
  instructions, overcoming typical magic byte and other input checks. Grimoire
  attempts to identify keywords and syntax from fuzz inputs in order to generate
  more clever large-scale mutations.

For details on Redqueen, Grimoire, IJON, Nyx, please visit [nyx-fuzz.com](https://nyx-fuzz.com).

## Components

The project is structured around multiple components:

- [`IntelLabs/kAFL`](https://github.com/IntelLabs/kAFL): The main repository which organises all subcomponents
- [`IntelLabs/kafl.fuzzer`](https://github.com/IntelLabs/kafl.fuzzer): The fuzzer frontend
- [`IntelLabs/kafl.qemu`](https://github.com/IntelLabs/kafl.qemu): Modified QEMU with snapshots
- [`IntelLabs/kafl.libxdc`](https://github.com/IntelLabs/kafl.libxdc): Fast Intel PT decoding library
- [`IntelLabs/kafl.targets`](https://github.com/IntelLabs/kafl.targets): Example kAFL targets


# Getting started

## Platform Requirements

- The setup requires a Gen-6 or newer Intel CPU (for Intel PT) and sufficient
  RAM to run several VMs at once.
- A modifed Linux host kernel is required for VM-based snapshot fuzzing with
  Intel PT coverage feedback. Setup inside VM or container is currently not supported!

## Local Installation

The userspace installation and fuzzing workflow has been tested for recent
Ubuntu (>=20.04) and Debian (>=bullseye). The base installation is captured
as an Ansible workflow which you can bootstrap using Python:

~~~sh
sudo apt-get install python3 python3-venv
make deploy
~~~

Ansible setup will ask for your root password.
If you are using a _passwordless sudo_ setup, just skip this by pressing enter.

## Remote Installation

kAFL's deployment offers the possibility of remote installation using Ansible.
Update the `deploy/inventory` file according to the [Ansible inventory
guide](https://docs.ansible.com/ansible/latest/user_guide/intro_inventory.html)
and make sure to **remove** the first line:

> localhost ansible_connection=local


Deployment will install kAFL to `$HOME/kafl` of the target machines:

~~~sh
make deploy
~~~

Note:
- If your nodes require a proxy setup, update the `group_vars/all.yml`.
- Check Ansible documentation for how to manage remote access.


# Next Steps

## Activate the Environment

To work with the installation, activate the environment in your shell:

~~~sh
make env
~~~

## Example Targets

Now that kAFL has been installed, you can continue by checking one of the example targets available.

Clone the [kafl.targets](https://github.com/IntelLabs/kafl.targets) repo into `<install_dir>/targets`:

~~~sh
make deploy -- --tags targets
~~~

The following examples are suitable as out-of-the-box test cases:
- [Linux kernel](https://github.com/IntelLabs/kafl.targets/tree/master/linux-kernel): Fuzz an OS kernel with a kAFL agent (harness) directly in the target
- [Zephyr RTOS](https://github.com/IntelLabs/kafl.targets/tree/master/zephyr_x86_32): Simple fuzzing test cases based on Zephyr RTOS
- [Windows](https://github.com/IntelLabs/kAFL/issues/53): This links to an opened issue since it's a WIP
