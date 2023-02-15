# Quick reference

-	**Maintained by**:  
	[Intel Corporation](https://github.com/IntelLabs/kAFL)

-	**Where to get help**:  
	[Discussions](https://github.com/IntelLabs/kAFL/discussions), [Issues](https://github.com/IntelLabs/kAFL/issues)


# Supported tags and respective `Dockerfile` links

-	[`latest`](https://github.com/IntelLabs/kAFL/blob/master/Dockerfile), [`master`](https://github.com/IntelLabs/kAFL/blob/master/Dockerfile)


# kAFL

This image allows you to run the [kAFL fuzzer](https://github.com/IntelLabs/kafl.fuzzer) packaged as a convenient Docker container.

It contains all the userland kAFL components required to execute the fuzzer (custom QEMU, libxdc, capstone, radamsa and the Python fuzzer frontend).

A [kAFL-compatible kernel](https://github.com/IntelLabs/kafl.linux) is required to fuzz a given target.

# How to use this image ?

➡️ Please check the [official installation guide](https://intellabs.github.io/kAFL/tutorials/installation.html) and follow the setup path that uses a Docker image.

➡️ You can pursue with the [linux kernel fuzzing tutorial](https://intellabs.github.io/kAFL/tutorials/fuzzing_linux_kernel.html)

This image requires specific Docker parameters to be launched:

Let's take an example of fuzzing the Linux Kernel:

~~~bash
docker run \
        -ti --rm \
        --device /dev/kvm \
        -v my_workdir:/mnt/workdir \
        -v my_kernel:/mnt/kernel \
        --user $(id -u):$(id -g) \
        --group-add $(getent group kvm | cut -d: -f3) \
        intellabs/kafl \
        --purge \
        -w /mnt/workdir \
        --redqueen --grimoire -D --radamsa \
        --kernel /mnt/kernel \
        -t 0.1 -ts 0.01 -m 512 --log-crashes -p 2
~~~

- `--device /dev/kvm`: `/dev/kvm` needs to be exposed in the Docker container for QEMU to issue `ioctls`
- `-v my_workdir:/mnt/workdir`: exposing our [kAFL workdir](https://intellabs.github.io/kAFL/reference/fuzzer_configuration.html#work-dir) as a volume in the container. Note: you need to create this directory by yourself before launching the container, otherwise it will be created by the Docker daemon as `root:root`
- `-v my_kernel:/mnt/kernel`: exposing our kernel to be fuzzed as a volume in the container
- `--user $(id -u):$(id -g)`: execute kAFL as the same host user to preserve permissions on the mounted workdir
- `--group-add $(getent group kvm | cut -d: -f3)`: add the container user in the host `kvm` group. This is required to write `ioctls` on `/dev/kvm`, which has `root:kvm` file permissions
- `intellabs/kafl`: the name of this image
- `--purge ...`: kAFL command line parameters
