# kAFL Userspace Fuzzing

This directly contains sample scripts for launching Linux userspace binaries in kAFL. 

The selected target binary is packaged into an initrd and launched via `qemu -kernel -initrd`.
An embedded `LD_PRELOAD` forkserver is used to map kAFL hypercalls to AFL-style I/O inside the guest.

The scripts are sufficiently clever to launch typical AFL benchmark binaries
such as those in the binutils package. The required shared libraries are
automatically copied from the host system into the initrd.

Example use:

```
# fetch, build, and pack it up for VM fuzzing
$ ./tests/user_bench/build.sh help
$ ./tests/user_bench/build.sh bison
$ ./tests/user_bench/run.sh pack bison

# actually fuzz it
$ ./tests/user_bench/run.sh run bison -v
```
