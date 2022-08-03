<h1 align="center">
  <br>kAFL</br>
</h1>

<h3 align="center">
HW-assisted Feedback Fuzzer for x86 VMs
</h3>

<p align="center">
  <a href="https://github.com/IntelLabs/kAFL/actions/workflows/CI.yml">
    <img src="https://github.com/IntelLabs/kAFL/actions/workflows/CI.yml/badge.svg" alt="CI">
  </a>
  <a href="https://wenzel.github.io/kAFL/">
    <img src="https://img.shields.io/badge/Online-Documentation-green?style=for-the-badge&logo=gitbook" alt="online_docs"/>
  </a>
</p>

_kAFL_/_Nyx_ is a fast guided fuzzer for the x86 VM. It is great for anything that
executes as _QEMU_/_KVM_ guest, in particular x86 firmware, kernels and full-blown
operating systems.

## Building the documentation

The project's documentation is hosted online at [![online_docs](https://img.shields.io/badge/Online-Documentation-green)](https://wenzel.github.io/kAFL/)

To build the docs locally:
~~~
cd docs
make html
xdg-open build/html/index.html
~~~
