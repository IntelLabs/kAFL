# Getting started

## Requirements

- The setup requires a Gen-6 or newer Intel CPU (for Intel PT) and sufficient
  RAM to run several VMs at once.
- A modifed Linux host kernel is required for VM-based snapshot fuzzing with
  Intel PT coverage feedback. Setup inside VM or container is not supported at
  this point.
- The userspace installation and fuzzing workflow has been tested for recent
Ubuntu (>=`20.04`) and Debian (>=`bullseye`).
- The _Python3_ interpreter and its `venv` module is required:

~~~sh
sudo apt-get install python3 python3-venv
~~~

## Installation

::::{tab-set}

:::{tab-item} Local
The base installation is captured as an Ansible playbook which you can launch as follows:

~~~sh
make deploy
~~~

Ansible setup will ask for your root password.
If you are using a _passwordless sudo_ setup, just skip this by pressing enter.
:::

:::{tab-item} Remote
kAFL's deployment offers the possibility of remote installation using Ansible.
Update the `deploy/inventory` file according to the [Ansible inventory
guide](https://docs.ansible.com/ansible/latest/user_guide/intro_inventory.html)
and make sure to **remove** the `localhost` host:

~~~
localhost
~~~

Deployment will install kAFL to `$HOME/kafl` of the target machines:

~~~sh
make deploy
~~~

Note:
- If your nodes require a proxy setup, update the `group_vars/all.yml`.
- Check Ansible documentation for how to manage remote access.
:::

::::

## Next Steps

### Activate the Environment

To work with the installation, activate the environment in your shell:

~~~sh
make env
~~~

### Example Targets

Now that kAFL has been installed, you can continue by checking one of the example targets available.

Clone the [kafl.targets](https://github.com/IntelLabs/kafl.targets) repo into `<install_dir>/targets`:

~~~sh
make deploy -- --tags targets
~~~

The following examples are suitable as out-of-the-box test cases:
- [Linux kernel](https://github.com/IntelLabs/kafl.targets/tree/master/linux-kernel): Fuzz an OS kernel with a kAFL agent (harness) directly in the target
- [Zephyr RTOS](https://github.com/IntelLabs/kafl.targets/tree/master/zephyr_x86_32): Simple fuzzing test cases based on Zephyr RTOS
- [Windows](https://github.com/IntelLabs/kAFL/issues/53): This links to an opened issue since it's a WIP
