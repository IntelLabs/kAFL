# Deployment

kAFL's deployment system (_or installation_) is built around [Ansible](https://www.ansible.com/), an IT automation framework
useful for deploying Cloud services and provisioning virtual machines.

:::{note}
As a user, you are only expected to update the Ansible [🗋 `deploy/inventory`](https://github.com/IntelLabs/kAFL/blob/master/deploy/inventory) if you want to perform a remote deployment. See Ansible's [inventory documentation](https://docs.ansible.com/ansible/latest/user_guide/intro_inventory.html).
:::

## System modifications

This is the list system level modifications made by the Ansible playbook when installing _kAFL_:

- checking for KVM's compatibility with kAFL. If necessary, setup a new kernel:
  - [download](https://github.com/IntelLabs/kafl.linux/releases/tag/kvm-nyx-5.10.73)
  - install (`5.10.73`)
  - update _GRUB_
  - reboot
- ensure current user is in `kvm` group
- ensure `/dev/kvm` device has permissions for the `kvm` group


## Makefile targets


| Target   | Description                                                                                                                    | EXTRA_ARGS |
| -------- | ------------------------------------------------------------------------------------------------------------------------------ | ---------- |
| `deploy` | Deploys kAFL components according to the playbook and the `deploy/inventory` file. Will be deployed on `localhost` by default. | ☑️         |
| `env`    | Enters a new sub-shell with the kAFL environment variables set.                                                                |            |
| `clean`  | Removes the _virtualenv_ `deploy/venv`                                                                                         |            |
| `update` | Forces to `git pull` on every repository managed by the playbook. Developer oriented target. Uses the `clone` _Ansible_ tag.   | ☑️         |
| `build`  | Rebuilds every component that can be built. Developer oriented target. Uses the `build` _Ansible_ tag.                         | ☑️         |



::::{admonition} EXTRA_ARGS
:class: note

Some Makefile targets can accept additional command line arguments (`EXTRA_ARGS`) by specifying them after the end of command options symbol (a double dash `--`).

These arguments will be passed to the underlying _Ansible_ command line.

Example:
~~~shell
# toggle Ansible 3rd level verbosity
make deploy -- -vvv
# toggle the 'kernel' Ansible tag
make deploy -- --tags kernel
# skip the hardware_check Ansible tag
make deploy -- --skip-tags hardare_check
~~~
:::{warning}
Since we use a [Makefile hack](https://stackoverflow.com/a/14061796/3017219) to convert additional targets as `EXTRA_ARGS`, it's not possible to use keyword arguments, or pass a quoted string:

Example:
~~~shell
# doesn't work
make deploy -- --extra-vars ansible_connection=local
make deploy -- --extra-vars '{"ansible_connection": "local"}'
~~~
:::
::::

## Ansible tags

A set of [_Ansible_ tags](https://docs.ansible.com/ansible/latest/user_guide/playbooks_tags.html) are available to have fine grained control on the playbook's execution.

They can be toggled or skipped with the [`--tags`](https://docs.ansible.com/ansible/latest/cli/ansible-playbook.html#cmdoption-ansible-playbook-2) and [`--skip-tags`](https://docs.ansible.com/ansible/latest/cli/ansible-playbook.html#cmdoption-ansible-playbook-skip-tags) _Ansible_ command line parameters, and directly added from the makefile target via `EXTRA_ARGS` feature (described previously).

| Tag              | Description                                                                                                                    |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| `kernel`         | Selects the [kernel](https://github.com/IntelLabs/kafl.linux) tasks                                                            |
| `radamsa`        | Selects the [radamsa](https://gitlab.com/akihe/radamsa) tasks                                                                  |
| `capstone`       | Selects the [capstone](https://github.com/aquynh/capstone) tasks                                                               |
| `libxdc`         | Selects the [libxdc](https://github.com/IntelLabs/kafl.libxdc) tasks                                                           |
| `qemu`           | Selects the [QEMU](https://github.com/IntelLabs/kafl.qemu) tasks                                                               |
| `fuzzer`         | Selects the [fuzzer](https://github.com/IntelLabs/kafl.fuzzer) tasks                                                           |
| `hardware_check` | Selects the hardware/kernel requirements checking tasks. Introduced to be skipped on the CI runs.                                     |
| `kvm_device`     | Selects the tasks related to fixing permissions on the KVM node device. Introduced to be skipped on the CI runs.               |
| `reboot_kernel`  | Selects the task responsible for rebooting the remote node after kernel installation. Introduced to be skipped on the CI runs. |
| `update_grub`    | Selects the tasks related to GRUB entry update after kernel installation. Introduced to be skipped on the CI runs.             |
| `build`          | Selects all tasks where a component can be rebuild (`QEMU`, `libxdc`, etc ...). Developer oriented tag.                        |
| `clone`          | Selects all tasks where a repository is cloned. Developer oriented tag.                                                        |


:::{note}
You can list available tags with

~~~shell
make deploy -- --list-tags
~~~
:::

## Ansible Galaxy and composability

One of the reasons to rewrite kAFL's deployment from scratching for the [`v0.5`](https://github.com/IntelLabs/kAFL/releases/tag/v0.5) release was to achieve a better composability.

In fact, other projects at Intel are based on kAFL, like the [ccc-linux-guest-hardening](https://github.com/intel/ccc-linux-guest-hardening) repo. And we expect the community to develop their own tooling and use cases based on kAFL.

We wanted to make it as easy as possible to reuse the current kAFL deployment and cherry-pick the desired components. With this goal in mind, we leveraged a powerful feature of _Ansible_: [Ansible Galaxy](https://galaxy.ansible.com/) to breakdown kAFL's setup into modular [roles](https://docs.ansible.com/ansible/latest/user_guide/playbooks_reuse_roles.html), and distribute them into a reusable [collection](https://docs.ansible.com/ansible/devel/dev_guide/developing_collections.html#developing-collections).

### intellabs.kafl Ansible collection

The [`intellabs.kafl`](https://github.com/IntelLabs/kAFL/tree/master/deploy/intellabs/kafl) collection is available in the [📁`deploy`](https://github.com/IntelLabs/kAFL/tree/master/deploy) directory.

It regroups all the essential components required to setup kAFL (kernel package, QEMU, libxdc, capstone, fuzzer frontend ...).

The roles are depending on each other, in such a way that including the `fuzzer` role will pull out the others:

~~~yaml
  roles:
    - role: intellabs.kafl.fuzzer
~~~

```{mermaid}
flowchart LR
    fuzzer --> kernel
    fuzzer --> qemu
    fuzzer --> radamsa
    qemu --> capstone
    qemu --> libxdc
```

### Reusing the collection

[kAFL](https://github.com/IntelLabs/kAFL) and [ccc-linux-guest-hardening](https://github.com/intel/ccc-linux-guest-hardening) are sharing the same deployment for kAFL.

:::{note}
Since the collection is hosted in the top-level _kAFL_ repository, it is included locally by specifying the source directory path.

_ccc-linux-guest-hardening_ on the other hand, needs to specify the git repository and the subfolder.
:::

```{mermaid}
flowchart LR
    kAFL==>|source: ./intellabs/kafl|intellabs.kafl
    ccc-linux-guest-hardening==>|source: git+https://github.com/IntelLabs/kAFL#/deploy/intellabs/|intellabs.kafl
```

:::{note}
The [`intellabs.kafl`](https://github.com/IntelLabs/kAFL/tree/master/deploy/intellabs/kafl) Ansible collection is not yet publicly distributed on the [Ansible Galaxy](https://galaxy.ansible.com/) website.

It can be referenced in your [`requirements.yml`](https://docs.ansible.com/ansible/latest/galaxy/user_guide.html#install-multiple-collections-with-a-requirements-file) via the git repository:
~~~yaml
collections:
  - name: intellabs.kafl
    source: git+https://github.com/IntelLabs/kAFL#/deploy/intellabs/
    type: git
    version: master
~~~
:::
