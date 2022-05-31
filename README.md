<h1 align="center">
  <br>kAFL</br>
</h1>

<h3 align="center">
HW-assisted Feedback Fuzzer for x86 VMs
</h3>

<p align="center">
  <a href="https://github.com/Wenzel/kAFL/actions/workflows/CI.yml">
    <img src="https://github.com/Wenzel/kAFL/actions/workflows/CI.yml/badge.svg" alt="CI">
  </a>
</p>


kAFL/Nyx is a fast guided fuzzer for the x86 VM. It is great for anything that
executes as Qemu/KVM guest, in particular x86 firmware, kernels and full-blown
operating systems.

kAFL now leverages the greatly extended and improved [Nyx backend](https://nyx-fuzz.com).

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

## Requirements

- `python3`
- `python3-venv`

~~~
sudo apt-get install python3 python3-venv
~~~

## Setup

kAFL's deployment offers the possibility of local or remote installation.

In both cases, you will find in the installation directory:
- `.env` file: useful environment variables for your scripts
- `.venv` Python virtual environment: where kAFL fuzzer is installed


### Local

- installation directory: `<repo_root>/kafl`

~~~
make deploy_local
~~~

You will be prompted for your root password.
If you are using a _passwordless sudo_ setup, just skip this by pressing enter.

### Remote

- installation directory: `$HOME/kafl`

You will have to create an `inventory` file to describe your nodes, according to [Ansible's inventory guide](https://docs.ansible.com/ansible/latest/user_guide/intro_inventory.html)

~~~
make deploy
~~~

Note: if your nodes require a proxy setup, update the `group_vars/all.yml`.
