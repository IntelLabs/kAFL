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

# 📖 Documentation

- Misc fixes (#213)
- Linux kernel tutorial: use implicit IP filters from snapshot metadata: (https://intellabs.github.io/kAFL/reference/hypercall_api.html#range-submit) (#216)


# 🧰 Behind the scenes

/
