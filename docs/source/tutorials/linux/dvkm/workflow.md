# 2 - kAFL workflow

This section focuses on setting up a development workflow for virtualizing our target with QEMU/KVM and interfacing it with kAFL.

A streamlined workflow enables rapid iterations while adjusting the harness and obtaining feedback from the fuzzing campaign.

Concepts introduced:

- kAFL QEMU inputs parameter:
  - [`qemu_image`](../../../reference/fuzzer_configuration.md#qemu_image)
  - [`qemu_kernel`](../../../reference/fuzzer_configuration.md#qemu_kernel), [`qemu_append`](../../../reference/fuzzer_configuration.md#qemu_append) [`qemu_initrd`](../../../reference/fuzzer_configuration.md#qemu_initrd)
- [linux-user](https://github.com/IntelLabs/kafl.targets/tree/master/linux-user) agent.sh workflow: for a simple yet effective setup targeting Linux userspace and drivers.
- kAFL [`sharedir`](../../../reference/fuzzer_configuration.md#sharedir) parameter: enables efficient file-based guest-host communication on top of kAFL hypercalls.

## Virtualizing our target

### QEMU Image

Traditional QEMU/KVM virtualization would necessitate creating a complete, bootable QEMU image.

Although feasible, this approach presents several practical challenges:

- 1. Download and install a fresh Ubuntu image, or equivalent
- 2. Download our kafl target into the VM
- 3. Compile it, and configure it to load during the boot sequence.
- 4. Export the image and use it as kAFL [`qemu_image`](../../../reference/fuzzer_configuration.md#qemu_image) parameter

```{code-block} shell
---
caption: Example using `qemu_image` (`--image` commandline) kAFL parameter
---
(venv) $ kafl fuzz --image /path/to/ubuntu-target.qcow2
```

- 5. Repeat steps `3-4` on each iteration of the harness or target update

```{mermaid}
flowchart TD
    subgraph "QEMU image workflow"
        install("1. Setup Ubuntu VM image") --> transfer("2. Download or update our kAFL target")--> compile("3. Compile it") --> insert("4. Insert into the boot sequence")
        insert -.- export[/"5. Export the image for QEMU/KVM
                            (if necessary)"/]
        export -.- fuzz["6. Fuzz with kAFL"]
        fuzz --> update_need{"7. Target update ?
                            (code or harness)"}
        update_need -->|Yes| transfer
        update_need -->|No| Run["8. Run the full fuzzing campaign"]
    end
```

Updating the target in this workflow is cumbersome and may require the VM to be booted or its image restored from a snapshot.

Additionally, you must set up a communication channel with the VM. Several options are available for this, including: 

- Simple SSH server
- [Plan 9 VirtFS](https://wiki.qemu.org/Documentation/9psetup)
- [QEMU Guest Agent](https://wiki.qemu.org/Features/GuestAgent)
- [SMB](https://ubuntu.com/tutorials/install-and-configure-samba#1-overview)/[NFS](https://ubuntu.com/server/docs/service-nfs)
- [Ansible playbook](https://docs.ansible.com/ansible/latest/playbook_guide/playbooks_intro.html)

:::{note}
The [Windows driver](../../windows/driver/index.md) example target demonstrates how to combine [Packer](https://www.packer.io/), [Vagrant](https://www.vagrantup.com/), and [Ansible](https://docs.ansible.com/ansible/latest/playbook_guide/playbooks_intro.html) with [WinRM](https://learn.microsoft.com/en-us/windows/win32/winrm/portal) channel to provide a convenient setup.
:::

### Direct Kernel Boot and initrd

Open source kernel and firmware targets can often be booted using QEMU's [Direct Linux Boot](https://qemu-project.gitlab.io/qemu/system/linuxboot.html) feature.

This approach is often more efficient than bootng a full-VM image and easier to customize and script.

```{code-block} shell
---
caption: Example using `qemu_kernel` (`--kernel`) and `qemu_initrd` (`--initrd`) kAFL parameters
---
(venv) $ kafl fuzz --kernel /path/to/linux/arch/x86/boot/bzImage --initrd /path/to/initrd.cpio.gz
```

## Initrd and `agent.sh` workflow

The approach outlined here relies on crafting a custom initrd that boots into a minimal BusyBox root filesystem.

We'll utilize kAFL's [`sharedir`](../../../reference/fuzzer_configuration.md#sharedir) feature as an expedient communication channel between the host and guest.

This solution is implemented in the [`🗈 scripts/gen_initrd.sh`](https://github.com/IntelLabs/kafl.targets/blob/master/linux-user/scripts/gen_initrd.sh).

### `gen_initrd.sh`

```{mermaid}
flowchart TD
    subgraph "gen_initrd.sh"
      rootfs["Create BusyBox rootfs"] --> copy_t
      subgraph Inject template files
        copy_t["Install template files into rootfs"] --> copy_vmcall["Install vmcall into /fuzz"] --> copy_dep["Install required shared libraries"]
      end
      copy_dep --> bless["Chain loader.sh into init scripts"]
      bless --> gen["Generate final initrd.cpio.gz image"]

      click inject "https://github.com/IntelLabs/kafl.targets/tree/master/linux-user/initrd_template"
      click bless "https://github.com/IntelLabs/kafl.targets/blob/master/linux-user/scripts/gen_initrd.sh#L32"
    end
```

### `sharedir`

kAFL's sharedir feature enables a host file system directory to be exposed to the guest through its hypercall API.

```{code-block} shell
---
caption: Exposing the target directory
---
$ ls -l
📂 target
(venv) $ kafl fuzz --sharedir target
```

The following hypercalls are interacting with the sharedir:

- [`REQ_STREAM_DATA`](../../../reference/hypercall_api.md#req_stream_data): fetch a file from host -> guest
- [`REQ_STREAM_DATA_BULK`](../../../reference/hypercall_api.md#req_stream_data_bulk): fetch files from host -> guest (better performance)
- [`DUMP_FILE`](../../../reference/hypercall_api.md#dump_file): pushes a file from guest -> host

### `vmcall`

The [`📂 vmcall`](https://github.com/IntelLabs/kafl.targets/tree/master/linux-user/vmcall) binary is a utility that implements most of the hypercall interface, serving as a convenient tool within the guest environment.

```{code-block} shell
---
caption: Sending kAFL hprintf string
---
$ echo "Hello from vmcall" | vmcall hcat
```

```{code-block} shell
---
caption: Downloading file.txt from host sharedir into /fuzz
---
$ vmcall hget -x -o /fuzz file.txt
```

```{code-block} shell
---
caption: Sending guest /proc/modules to the host
---
$ vmcall hpush -o "modules" /proc/modules
```

### `agent.sh`

To streamline the development workflow and eliminate the need to recompile the initrd for every target update, `loader.sh` downloads an `agent.sh` script from the exposed `sharedir`, using `vmcall`.

```{mermaid}
flowchart TD
    subgraph "loader.sh"
      download["Download agent.sh with vmcall"] --> exec["Execute agent.sh"] --> log["Send agent.sh log output"]
    end
```

The agent.sh script's role is multifaceted. It downloads the `dvkm.ko` kernel module, loads it, and then initiates the fuzzing process.

```{mermaid}
flowchart TD
    subgraph "agent.sh"
      download_mod["Download dvkm.ko"] --> insert["Insert dvkm.ko"] --> download_test["Download fuzz_dvkm"]
      download_test --> fuzz["Start fuzzing
            (run fuzz_dvkm)"]
    end
```

### Summary

```{mermaid}
flowchart TD
    subgraph Initrd
      exec_load["Execute loader.sh"] --> dl_agent

      subgraph `loader.sh`
        dl_agent["Download agent.sh"] --> exec_agent["Execute agent.sh"] --> dl_mod
        subgraph `agent.sh`
          dl_mod["Download dvkm.ko"] --> insert["Insert dvkm.ko"] --> dl_fuzz["Download fuzz_dvkm"] --> fuzz["Start fuzzing"]
        end
      end
    end
```

With this workflow, we have a flexible setup, ideal to gather feedback, build our harness and make quick iterations !

## DVKM workflow setup

The `📂 linux-user/dvkm` directory structure is organized as follows:

```shell
$ ls -l
📂 Damn_Vulnerable_Kernel_Module
🗒️ kafl.yaml
🗒️ Makefile
📂 sharedir

$ ls -l sharedir
🗒️ agent.sh
➡️ dvkm.ko -> ../Damn_Vulnerable_Kernel_Module/dvkm.ko
➡️ fuzz_dvkm -> ../Damn_Vulnerable_Kernel_Module/test_dvkm

$ ls -l Damn_Vulnerable_Kernel_Module/
🗒️ dvkm.c
🗒️ LICENSE
🗒️ Makefile
🗒️ Module.symvers
🗒️ README.md
🗒️ test_dvkm.c
```

To set up the required dependencies, navigate to the kAFL directory and execute `make deploy`:

```shell
$ cd kAFL
(venv) $ make deploy -- --tags examples,examples-dvkm
```

Now, switch to the `📂 linux-user/dvkm` directory to compile the target and its dependencies:

```shell
$ cd kafl/examples/linux-user/dvkm
make
```

You have successfully compiled:
- the custom initrd
- the Linux kernel with kAFL modifications
- the dvkm module
- the kafl-agent implemented in `test_dvkm.c`

In the next part, we will focus on how to implement a kAFL harness, and look at the implementation details of DVKM !
