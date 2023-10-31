# Installation

Before we dive into the installation process, let's make sure that your local machine meets the necessary requirements
to run the fuzzer.

## 1. Requirements

### 1.1 Hardware

Your processor must support Intel Processor Trace (_Intel PT_). This feature is available on Gen-6 ([_Skylake_](https://www.intel.com/content/www/us/en/developer/articles/technical/an-overview-of-the-6th-generation-intel-core-processor-code-named-skylake.html#:~:text=Introduction-,The%206th%20generation%20Intel%C2%AE%20Core%E2%84%A2%20processor%20(code%2Dnamed,Skylake)%20was%20launched%20in%202015.)) or newer Intel processors.
:::{note}
Although Intel Gen-5 ([_Broadwell_](https://en.wikipedia.org/wiki/Broadwell_(microarchitecture))) [supports _Intel PT_](https://www.intel.com/content/www/us/en/support/articles/000056730/processors.html), some addional Intel PT features have been introduced in Gen-6 that are required for kAFL to execute properly.
:::

You can check your CPU's compatibility with the following command:
~~~shell
echo -n "Intel PT support: "; if $(grep -q "intel_pt" /proc/cpuinfo); then echo "✅"; else echo "❌"; fi
~~~
:::{tip}
kAFL's installation process will start by checking your processor's compatibility with _Intel PT_, and abort the installation if necessary.
:::

### 1.2 Software

kAFL userspace stack can be setup via 2 ways:
- Our [`Ansible playbook`](#3-deploying-kafl--make-deploy) (**recommended**)
- A prebuilt Docker image, which can be pulled from Dockerhub at [`intellabs/kafl:latest`](https://hub.docker.com/r/intellabs/kafl)

:::{note}
This Ansible playbook methods is recommended as it will give you a better understanding what gets installed, configured, and how.

Furthermore, you will be able to modify these components and update them, should it be necessary for your target.

Additionally, the docker command line is more complex since it requires mounting volumes into the container, and isn't recommended unless you are very familiar with the tool.
:::

The requirements for either of these setups:
:::::{tab-set}
::::{tab-item} Local setup
- _Python 3_ interpreter (`>= 3.9`)
- _Git_
- Essential toolchain to build software (`make`, `gcc`, ...)

The following command will install the required software on Ubuntu
```shell
sudo apt-get install -y python3-dev python3-venv git build-essential
```

:::{note}
The userspace installation and fuzzing workflow has been tested for recent
Ubuntu (>=`20.04`) and Debian (>=`Bullseye`).
:::
::::
::::{tab-item} Docker image
- [Docker](https://www.docker.com/)
::::
:::::

::::{important}
The installation will require to download, install and **reboot** your system on a **modifed Linux kernel**.
:::{note}
Setup inside VM is not supported at this point.
:::
::::

## 2. Cloning the sources

First clone the sources from the main kAFL repository on Github, and move into the directory

~~~shell
git clone https://github.com/IntelLabs/kAFL
cd kAFL
~~~

## 3. Deploying kAFL : `make deploy`

:::::{tab-set}
::::{tab-item} Local setup
Run the `deploy` make target to start the installation.

~~~shell
make deploy
~~~
::::
::::{tab-item} Docker image
If you follow the Docker image based setup for kAFL, you only need to install the kAFL kernel.

This can be done with `make deploy`, by specifying an `Ansible` tag.

~~~shell
make deploy -- --tags kernel
~~~
::::
:::::

The next step will trigger kAFL installation.
::::{important}
Before continuing, you might want to check the [system changes](../reference/deployment) made by the installation.

:::{tip}
If you want a glimpse of the installation execution, without actually touching anything on your system (_dry-run_), you can use the following command:

~~~
make deploy -- --check
~~~
Skip the prompt by pressing `ENTER`.
:::
::::

Once you are confortable with the changes that will be made to your system, execute the `deploy` make target.

::::{important}
You will be prompted for your root password by kAFL's deployment tool ([_Ansible_](https://docs.ansible.com/ansible/latest/cli/ansible-playbook.html#cmdoption-ansible-playbook-K))

This is necessary to allow system modifications.
~~~
BECOME password:
~~~
:::{tip}
The following message will be displayed before:

~~~shell
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Ansible BECOME password: if you are using a passwordless SUDO, skip by pressing enter.┃
└━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┘
~~~
In fact, if your current user doesn't require any password (`user ALL=(ALL) NOPASSWD: ALL` in `sudoers`), you can just press `ENTER`.
:::
::::

## 4. Setting kAFL environment : `make env`

::::{tab-set}
:::{tab-item} Local setup
Once the setup is complete, you can now run the `env` target.

This command will start a new sub-shell, and source the newly created `env.sh` file to setup the kAFL environment variables.

~~~
make env
~~~
:::
:::{tab-item} Docker image
Nothing to be done here.
You are good to go !
:::
::::


## 5. Verify the installation

::::{tab-set}
:::{tab-item} Local setup
To verify the installation, you should have the `kafl fuzz` binary available in your `PATH`, and execute it from your new sub-shell:

~~~
$ kafl fuzz
~~~
:::
:::{tab-item} Docker image
Let's pull the [`intellabs/kafl`](https://hub.docker.com/r/intellabs/kafl) image

~~~shell
docker pull intellabs/kafl
~~~

And execute the `fuzz` subcommand !

~~~shell
docker run \
        -ti --rm \
        --device /dev/kvm \
        --user $(id -u):$(id -g) \
        --group-add $(getent group kvm | cut -d: -f3) \
        intellabs/kafl \
        fuzz
~~~
:::
::::


You should see the kAFL ACSII art logo:

~~~

    __                        __  ___    ________
   / /_____  _________  ___  / / /   |  / ____/ /
  / //_/ _ \/ ___/ __ \/ _ \/ / / /| | / /_  / /
 / ,< /  __/ /  / / / /  __/ / / ___ |/ __/ / /___
/_/|_|\___/_/  /_/ /_/\___/_/ /_/  |_/_/   /_____/
===================================================

<< kAFL Fuzzer >>
~~~

:::{note}
The complete documentation regarding kAFL's installation is available at [reference/deployment](../reference/deployment)
:::

## 6. On to the next steps !

Now you are ready to configure one of our pre-baked kAFL targets, and start the fuzzer !

- ➡️ Continue by [fuzzing on Linux](./linux/index.md)
- ➡️ Continue by [fuzzing Windows programs](./windows/index.md)
