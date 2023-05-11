# Github Actions CI/CD

kAFL can be integrated into your Github Actions CI/CD pipeline, thanks to the [`IntelLabs/kafl.actions`](https://github.com/IntelLabs/kafl.actions).

It acts as a basic-block to compose your workflows with kAFL.

With this Action you can:

- automate the fuzzing process of your target and building a reusable workflow
- delegate the kAFL setup from your local machine to a reproducible infrastucture
- build a regression test suite, continuously updated with new seeds, to be executed at your convenience (every PR, day, week, ...)

Requirements:

- A kAFL-compatible server (**Intel PT**) acting as [Github Action Self-Hosted Runner](https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/about-self-hosted-runners)


## 1 - Deploying the kernel

This first step will install the kAFL on the server of your choice.

We can leverage kAFL's [Ansible playbook](../reference/deployment.md) to automate this part.

```bash
cd kAFL
# rewrite the Ansible inventory to deploy remotely on a specified server
echo 'kafl-actions-runner.example.com' > deploy/inventory
# only deploy the kernel
make deploy -- --tags kernel
```

:::{note}
This command will:
- install the kernel
- update GRUB 
- **reboot** the server
:::

➡️ Once this is done, you should find a `-nyx` tag in your server's `uname`
```bash
uname -a | grep nyx
... 6.0.0-nyx+ ...
```

## 2 - Setting up Docker

[`kafl.actions`](https://github.com/IntelLabs/kafl.actions) will pull the latest [`intellabs/kafl`](https://hub.docker.com/r/intellabs/kafl) Docker image to run the kAFL userspace.

Let's setup Docker on the runner as well !

➡️ [Install Docker Engine on Ubuntu](https://docs.docker.com/engine/install/ubuntu/)

## 3 - Setup the Github Actions Runner

Finally you can follow Github's official guide to add a [Self-Hosted Runner](https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/adding-self-hosted-runners#adding-a-self-hosted-runner-to-a-repository) to your repository.

You should now have a runner available under `Settings` `Actions` `Runners`

![kafl_runner](kafl_runner_added.png)

## 4 - Using `kafl.actions`

Go check [`kafl.actions`](https://github.com/IntelLabs/kafl.actions)'s README and the example [`kernel.yml`](https://github.com/IntelLabs/kafl.actions/blob/master/.github/workflows/kernel.yml) to fuzz the Linux kernel !

It boils down to invoking the action, specifing the subcommand, the workdir (to be mounted in the container), and a few `extra_args` for the kAFL command line.

```yaml
  - name: Fuzz Linux kernel
    uses: IntelLabs/kafl.actions@master
    with:
        action: fuzz
```

Build your own workflows, automate and fuzz all the things (continuously) !

:::{note}
The default timeout for a Github Action's job is limited to `6h`.

It's possible to bypass this limit by specifying a higher value in [`jobs.<job_id>.timeout-minutes`](https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#jobsjob_idtimeout-minutes).

For example, you can set it to 2 weeks:
```yaml
jobs:
  fuzz:
    # bypass 6h limitation
    # set to 2 weeks max job execution time
    # 60 * 24 * 7 * 2 = 20160 minutes
    timeout-minutes: 20160
```

And then limit your target fuzzing to any value you want (under that threshold):
```yaml
  - name: Fuzz Linux kernel
    uses: IntelLabs/kafl.actions@master
    with:
      action: fuzz
      # 3 days
      # 60 * 60 * 24 * 3 = 259200 seconds
      timeout: 259200
```
````{warning}
[kafl.actions](https://github.com/IntelLabs/kafl.actions)'s fuzz timeout is specified in **seconds**, not minutes.
````
:::

## References

The [`kafl.actions`](https://github.com/IntelLabs/kafl.actions) Github Action has been introduced to the [Tianocore community meeting](https://www.youtube.com/watch?v=0adtDjSdSjc&t=230s) on May 4th 2023.
