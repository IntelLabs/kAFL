# 🌟 Features

/

# ✨ Improvements

- Fuzzer / QEMU:
  Dump snapshot metadata into `$WORKDIR/snapshot/state.yml`, and parse that file on fuzzer shutdown to update it's own IP filters configuration. (see [`kafl.fuzzer#68`](https://github.com/IntelLabs/kafl.fuzzer/pull/68), [`kafl.qemu#10`](https://github.com/IntelLabs/kafl.qemu/pull/10))

  This avoids having to pass IP filters through the `hprintf` channel, parse logs and extract them on the host, to send them again to `kafl cov` for coverage.

# 🔧 Fixes

- Security fixes (#215, #217)
- Switch QEMU revision pinning to a tag instead of a branch (#214)
- `kafl.targets`: simplify linux kernel tutorial and use predefined load path for kAFL configuration ([`kafl.targets#23`](https://github.com/IntelLabs/kafl.targets/pull/23))
- examples role
  - fix shell used to unpacking GPG key (#233)
  - install missing qemu-system-x86 package (#234)
  - disable cloning submodules (#256)
- libxdc/QEMU: fix regression observed with the 6.0 Nyx kernel (#253)
- CI: upgrade docs workflow to Python 3.9 (#255)

# 📖 Documentation

- Add new Linux tutorial based on DVKM (*Damn Vulnerable Kernel Module*) (#250)
- Misc fixes (#213)
- Linux kernel tutorial: use implicit IP filters from snapshot metadata: (https://intellabs.github.io/kAFL/reference/hypercall_api.html#range-submit) (#216)
- Fix `DUMP_FILE` hypercall argument (#254) (Thanks @sangjun !)

# 🧰 Behind the scenes

/
