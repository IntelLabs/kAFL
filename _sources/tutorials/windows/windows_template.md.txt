# 1. Windows VM Template

In order to execute the targets, we need a Windows VM to play with and configured to compile and load a driver.

Fortunately, we already provide this template and the necessary tooling under [`templates/windows`](https://github.com/IntelLabs/kafl.targets/tree/master/templates/windows).

Our Windows template is based on a [`Windows 10 Enterprise x64`](https://www.microsoft.com/en-us/evalcenter/download-windows-10-enterprise) image with `22H2` feature updates.

The following software is installed:

- MSVC compiler
- latest [SDK](https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/) and [WDK](https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk)
- WDK integration in Visual Studio
- Test mode enabled (load testsigned drivers)

:::{Note}
The template is simply a recipe to build Windows 10 and setup the software components mentionned above.

As a user, you are not receiving any license to any third-party software from Intel through this.
:::

## Setup the tooling

The following tooling is required to build and use the VM in our tutorial:

- [Packer](https://www.packer.io/): an image build automation tool that will be used to create the initial qcow2
- [Vagrant](https://www.vagrantup.com/): a simplified development environment to manage our VM and improve our workflow to edit the our harness sources, upload them and configure them to be triggered when Windows boot
- [Vagrant plugins](https://github.com/hashicorp/vagrant/wiki/Available-Vagrant-Plugins): A set of plugins extended the possiblities of vagrant. We will mainly use the [`vagrant-libvirt`](https://github.com/vagrant-libvirt/vagrant-libvirt) provider to import our VM under libvirt's `qemu:///session` connection.
- [Ansible and WinRM](https://docs.ansible.com/ansible/latest/os_guide/windows_winrm.html): Ansible will be used in conjonction with the Windows builtin `WinRM` node management protocol to provision the VM

The initial kAFL Ansible playbook that you have already used during the [installation](../installation.md#3-deploying-kafl--make-deploy) phase can be reused to install those tools !

We only need to specify some extra tags this time:

~~~shell
make deploy -- --tags examples,examples-template-windows
~~~

To verify your installation:

~~~shell
$ packer version
Packer v1.9.1 # or above
$ vagrant version
Installed Version: 2.3.6 # pinned 2.3.6
Latest Version: 2.3.7
...
$ vagrant plugin list
vagrant-host-shell (0.0.4, global) # or above
vagrant-libvirt (0.12.2, global) # or above
~~~

## Build the Windows VM Template

Now we can continue with building the actual image !

Let's move to the windows image template directory, and run the build:
~~~shell
cd kAFL/kafl/examples/templates/windows
make build
~~~

:::{Note}
Default values for allocated ressources to build the VM:
- `4` cpus
- `4G` of RAM

You can modify these values either in `win10.pkrvars.hcl`, or by updating the Packer command line in the `Makefile` `build` target:

~~~shell
packer build -var-file win10.pkrvars.hcl -var cpus=8 -var memory=8192 windows.pkr.hcl
~~~
::::{Note}
If for any reason you wish to opt-out of the automated provisioning step and want to setup the software components yourself (licensing issues, legal, etc),
you can remove the `provisioner "ansible"` section from the main `windows.pkr.hcl` template file.
::::
:::

You should get the following output:
~~~shell
source /home/user/kafl/kafl/examples/templates/windows/../../venv/bin/activate && packer build -var-file win10.pkrvars.hcl windows.pkr.hcl
qemu.windows: output will be in this color.

==> qemu.windows: Retrieving ISO
==> qemu.windows: Trying https://go.microsoft.com/fwlink/p/?LinkID=2208844&clcid=0x409&culture=en-us&country=US
==> qemu.windows: Trying https://go.microsoft.com/fwlink/p/?LinkID=2208844&checksum=sha256%3Aef7312733a9f5d7d51cfa04ac497671995674ca5e1058d5164d6028f0938d668&clcid=0x409&country=US&culture=en-us
==> qemu.windows: https://go.microsoft.com/fwlink/p/?LinkID=2208844&checksum=sha256%3Aef7312733a9f5d7d51cfa04ac497671995674ca5e1058d5164d6028f0938d668&clcid=0x409&country=US&culture=en-us => /home/user/.cache/packer/d731b3f758e61d53033aa8a67d3d8a3050aa1122.iso
==> qemu.windows: Creating floppy disk...
    qemu.windows: Copying files flatly from floppy_files
    qemu.windows: Copying file: answer_files/10/Autounattend.xml
    qemu.windows: Copying file: scripts/fixnetwork.ps1
    qemu.windows: Copying file: scripts/setup_winrm_public.bat
    qemu.windows: Done copying files from floppy_files
    qemu.windows: Collecting paths from floppy_dirs
    qemu.windows: Resulting paths from floppy_dirs : []
    qemu.windows: Done copying paths from floppy_dirs
    qemu.windows: Copying files from floppy_content
    qemu.windows: Done copying files from floppy_content
==> qemu.windows: Found port for communicator (SSH, WinRM, etc): 3573.
==> qemu.windows: Looking for available port between 5900 and 6000 on 0.0.0.0
==> qemu.windows: Starting VM, booting from CD-ROM
    qemu.windows: The VM will be run headless, without a GUI. If you want to
    qemu.windows: view the screen of the VM, connect via VNC without a password to
    qemu.windows: vnc://0.0.0.0:5973
==> qemu.windows: Overriding default Qemu arguments with qemuargs template option...
==> qemu.windows: Waiting 5s for boot...
==> qemu.windows: Connecting to VM via VNC (0.0.0.0:5973)
==> qemu.windows: Typing the boot commands over VNC...
    qemu.windows: Not using a NetBridge -- skipping StepWaitGuestAddress
==> qemu.windows: Using WinRM communicator to connect: 127.0.0.1
==> qemu.windows: Waiting for WinRM to become available...
~~~

Building the image and generating the build artifacts should take `~1h` to complete.

:::{warning}
If for any reason the build fails:

~~~python
==> qemu.windows: Error launching VM: Qemu failed to start. Please run with PACKER_LOG=1 to get more info.
~~~
You can set the environment variable `PACKER_LOG` to get more verbose output:

~~~shell
PACKER_LOG=1 make build
~~~
:::


## Import the template into Vagrant

Then, we will import the generated build artifact `packer_windows_libvirt.box` as a Box available for Vagrant.

Again, use the Makefile:

~~~shell
make import
~~~

Expected output
~~~shell
vagrant box remove kafl_windows || true
Box 'kafl_windows' (v0) with provider 'libvirt' appears
to still be in use by at least one Vagrant environment. Removing
the box could corrupt the environment. We recommend destroying
these environments first:

vagrant-kafl-windows (ID: aa61f0e482954cec9b853f9b8837a088)

Are you sure you want to remove this box? [y/N] y
Removing box 'kafl_windows' (v0) with provider 'libvirt'...
Vagrant-libvirt plugin removed box only from /home/user/.vagrant.d/boxes directory
From Libvirt storage pool you have to delete image manually(virsh, virt-manager or by any other tool)
vagrant box add packer_windows_libvirt.box --name kafl_windows
==> box: Box file was not detected as metadata. Adding it directly...
==> box: Adding box 'kafl_windows' (v0) for provider:
    box: Unpacking necessary files from: file:///home/user/kafl/kafl/examples/templates/windows/packer_windows_libvirt.box
==> box: Successfully added box 'kafl_windows' (v0) for 'libvirt'!
~~~

We can confirm that the box has been imported:
~~~shell
$ vagrant box list
kafl_windows (libvirt, 0)
~~~

## Import into libvirt

Finally, the last step of this section will be have a VM defined in libvirt's `qemu:///session` connection, and take a snapshot when WinRM is available,
so we can restore that snapshot and provision it right away !

Let's go to the `examples/windows-x86_64` folder and run `make init`
~~~shell
cd ../../windows_x86_64
make init
~~~

Expected output:
~~~shell
make[1]: Entering directory '/home/user/kafl/kafl/examples/windows_x86_64'
vagrant up --no-provision
Bringing machine 'vagrant-kafl-windows' up with 'libvirt' provider...
==> vagrant-kafl-windows: No version detected for kafl_windows, using timestamp to watch for modifications. Consider
==> vagrant-kafl-windows: generating a local metadata for the box with a version to allow better handling.
==> vagrant-kafl-windows: See https://www.vagrantup.com/docs/boxes/format#box-metadata for further details.
==> vagrant-kafl-windows: Creating image (snapshot of base box volume).
==> vagrant-kafl-windows: Creating domain with the following settings...
==> vagrant-kafl-windows:  -- Name:              windows_x86_64_vagrant-kafl-windows
==> vagrant-kafl-windows:  -- Description:       Source: /home/user/kafl/kafl/examples/windows_x86_64/Vagrantfile
==> vagrant-kafl-windows:  -- Domain type:       kvm
==> vagrant-kafl-windows:  -- Cpus:              4
==> vagrant-kafl-windows:  -- Feature:           acpi
==> vagrant-kafl-windows:  -- Feature:           apic
==> vagrant-kafl-windows:  -- Feature:           pae
==> vagrant-kafl-windows:  -- Clock offset:      utc
==> vagrant-kafl-windows:  -- Memory:            4096M
==> vagrant-kafl-windows:  -- Base box:          kafl_windows
==> vagrant-kafl-windows:  -- Storage pool:      default
==> vagrant-kafl-windows:  -- Image(vda):        /home/user/.local/share/libvirt/images/windows_x86_64_vagrant-kafl-windows.img, virtio, 64G
==> vagrant-kafl-windows:  -- Disk driver opts:  cache='default'
==> vagrant-kafl-windows:  -- Graphics Type:     spice
==> vagrant-kafl-windows:  -- Graphics Websocket:
==> vagrant-kafl-windows:  -- Graphics Port:
==> vagrant-kafl-windows:  -- Graphics IP:
==> vagrant-kafl-windows:  -- Graphics Password: Not defined
==> vagrant-kafl-windows:  -- Video Type:        cirrus
==> vagrant-kafl-windows:  -- Video VRAM:        16384
==> vagrant-kafl-windows:  -- Video 3D accel:    false
==> vagrant-kafl-windows:  -- Keymap:            en-us
==> vagrant-kafl-windows:  -- TPM Backend:       passthrough
==> vagrant-kafl-windows:  -- INPUT:             type=mouse, bus=ps2
==> vagrant-kafl-windows:  -- CHANNEL:             type=spicevmc, mode=
==> vagrant-kafl-windows:  -- CHANNEL:             target_type=virtio, target_name=com.redhat.spice.0
==> vagrant-kafl-windows: Creating shared folders metadata...
==> vagrant-kafl-windows: Updating domain definition due to configuration change
==> vagrant-kafl-windows: Starting domain.
==> vagrant-kafl-windows: Waiting for domain to get an IP address...
==> vagrant-kafl-windows: Waiting for machine to boot. This may take a few minutes...
    vagrant-kafl-windows: WinRM address: 192.168.122.168:5985
    vagrant-kafl-windows: WinRM username: vagrant
    vagrant-kafl-windows: WinRM execution_time_limit: PT2H
    vagrant-kafl-windows: WinRM transport: negotiate
==> vagrant-kafl-windows: Machine booted and ready!
==> vagrant-kafl-windows: Forwarding ports...
==> vagrant-kafl-windows: 5985 (guest) => 55985 (host) (adapter eth0)
==> vagrant-kafl-windows: 5986 (guest) => 55986 (host) (adapter eth0)
==> vagrant-kafl-windows: Machine not provisioned because `--no-provision` is specified.
vagrant snapshot save 'ready_provision'
==> vagrant-kafl-windows: Snapshotting the machine as 'ready_provision'...
==> vagrant-kafl-windows: Snapshot saved! You can restore the snapshot at any time by
==> vagrant-kafl-windows: using `vagrant snapshot restore`. You can delete it using
==> vagrant-kafl-windows: `vagrant snapshot delete`.
make[1]: Leaving directory '/home/user/kafl/kafl/examples/windows_x86_64'
~~~

Congratulations ! 🎉

You are now ready to setup our Windows targets and almost there to start fuzzing ! ⚡

- ➡️ Continue by [fuzzing userspace programs](./windows_userspace.md)
- ➡️ Continue by [fuzzing a driver](./windows_driver.md)
