# kAFL Setup for Fuzzing UEFI / OVMF

Example setup for fuzzing UEFI libraries or applications in kAFL.

The harness is build as an .efi application that is launched from EFI shell.
Other setups are possible, for example embedding the kAFL agent into early boot
OVMF modules to fuzz them more directly. It should also be possible to fuzz SMM
handlers using Qemu/KVM.

## Getting Started

Essentially you need to download and install EDK2. The harness is realized as
out-of-tree EFI applications. Qemu then offers an easy option to launch your
custom BIOS.

Below are further notes for manual setup/debug. Most of this is automated in `compile.sh`:

```
$ ./targets/uefi_ovmf_64/compile.sh edk2 # activate EDKII toolchain, download if not available
$ ./targets/uefi_ovmf_64/compile.sh ovmf # build OVMF
$ ./targets/uefi_ovmf_64/compile.sh app  # build kAFL sample
$ ./targets/uefi_ovmf_64/compile.sh run  # launch sample in kAFL
```

**Note:**
- kAFL requires an -ip0 parameter to indicate the address range of the target
  code inside the guest. The relevant load address of the .efi app can be
  extracted from the UEFI boot log (build OVMF with `-DDEBUG_ON_SERIAL_PORT`).
- To get you started, the helper script uses a very large (invalid) range
  leading to potential non-determinisim in the coverage feedback. The sample
  harnesses also print the address of the target function to the console.
- The custom OVMF or Qemu build appears to be sensitive to the overall memory
  given to the guest (-m). In case of erros, use below steps to validate that
  your OVMF build and app actually starts as expected.


## Tiano/EDK2 Setup

You need Tianocore EDKII to build OVMF, which basically UEFI for Qemu. Also depends on openssl.
If the `compile.sh` helper does not work for you, here are the basic steps:

- Basics:  https://github.com/tianocore/tianocore.github.io/wiki/Common-instructions
- OVMF:    https://github.com/tianocore/tianocore.github.io/wiki/How-to-build-OVMF
- OpenSSL: https://github.com/tianocore/edk2/blob/master/CryptoPkg/Library/OpensslLib/OpenSSL-HOWTO.txt

It typically boils down to this:

```
$ git clone https://github.com/tianocore/edk2 edk2.git
$ cd edk2.git
$ git checkout -b edk2-stable201905
$ git submodule update --init --recursive
$ make -C BaseTools
$ export EDK_TOOLS_PATH=$PWD/BaseTools
$ . edksetup.sh BaseTools
```

Set your build options in Conf/target.txt:

```
ACTIVE_PLATFORM       = OvmfPkg/OvmfPkgX64.dsc
TARGET_ARCH           = X64
TOOL_CHAIN_TAG        = GCC5
TARGET                = DEBUG
```

Try to build the OVMF package. In case of problems, check the wiki pages for help:

```
$ build
$ ls -l Build/OvmfX64/RELEASE_GCC5/FV/*.fd
$ cp Build/OvmfX64/RELEASE_GCC5/FV/OVMF.fd ~/kafl/bios.bin
```

## Debugging Qemu Startup

Qemu has multiple options to load PC firmware. You may find one to work better than others:
```
 -L:      qemu-system-x86_64 -L .
 -pflash: qemu-system-x86_64 -pflash bios.bin
 -bios:   qemu-system-x86_64 --bios bios.bin
```

Make sure that your bios.bin actually works (1) in KVM mode (2) with the same
Qemu version (3) with the patched/custom qemu build used by kAFL. Debug this
step first if it does not work and determine the required parameters/patches.
Compare against the command line used by kAFL (see debug.log).

This should get your bios.bin booted and land you into EFI shell:

```
$ ./qemu-4.0.0/x86_64-softmmu/qemu-system-x86_64 -enable-kvm --pflash bios.bin -net none -serial mon:stdio
```

Build an EFI app and test if it is presented and loaded properly in the VM:

```
$ ./targets/uefi_ovmf_64/compile.sh app
$ FAKE_HDA=$PWD/targets/uefi_ovmf_64/fake_hda
$ qemu-system-x86_64 -pflash bios.bin -hda fat:rw:$FAKE_HDA -net none -serial mon:stdio
```

## References

- https://github.com/shijunjing/edk2/tree/sanitizer

- https://edk2-docs.gitbooks.io/security-advisory/
- https://edk2-docs.gitbooks.io/security-advisory/edk-ii-tianocompress-bounds-checking-issues.html
- https://edk2-docs.gitbooks.io/security-advisory/stack-overflow-on-corrupted-bmp.html
