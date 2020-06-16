# Redqueen: Fuzzing with Input-to-State Correspondence 

<a href="https://www.ndss-symposium.org/ndss-paper/redqueen-fuzzing-with-input-to-state-correspondence/"> <img align="right" width="200"  src="rq_paper.png"> </a>

Redqueen is a fast general purpose fuzzer for x86 binary applications. It can automatically overcome checksums and magic bytes without falling back to complex and fragile program analysis techniques, such as symbolic execution. It works by observing the arguments to function calls and compare instructions via virtual machine introspection. Observed values are used to provide inputs specific mutations. More details can be found in the paper. This fuzzer is built upon [kAFL](https://github.com/RUB-SysSec/kAFL) and requires support for Intel VT-x as well as Intel Processor Trace. 

The <a href="https://www.ndss-symposium.org/ndss-paper/redqueen-fuzzing-with-input-to-state-correspondence/">Paper</a>, <a href="https://www.youtube.com/watch?v=9JpanJ29r_U">Talk</a> and <a href="https://hexgolems.com/talks/redqueen.pdf">Slides</a> describing Redqueen were published at NDSS 2019. 

## BibTex:
```
@inproceedings{redqueen,
  title={REDQUEEN: Fuzzing with Input-to-State Correspondence},
  author={Aschermann, Cornelius and Schumilo, Sergej and Blazytko, Tim and Gawlik, Robert and Holz, Thorsten},
  booktitle={Symposium on Network and Distributed System Security (NDSS)},
  year={2019},
}
```

### Initial Setup
To install redqueen run `install.sh`

```
cd ~/redqueen/
sh install.sh
```

This will setup everything, assuming an Ubuntu 16.04.

Fuzzing with Redqueen is a two stage process. First, the target application is packed:

```
python kAFL-Fuzzer/kafl_user_prepare.py \
       --recompile -args=/A -file=/A \
       targets/test_lava/binaries/who \
       targets/test_lava/packed/who/ m64
```

Pack an initrd with the required targets and dependencies:

```
bash targets/linux_x86_64-initramfs/pack.sh \
       targets/test_lava/packed/who/who_fuzz_initrd.gz \
       targets/test_lava/packed/who/who_fuzz

bash targets/linux_x86_64-initramfs/pack.sh \
       targets/test_lava/packed/who/who_info_initrd.gz \
       targets/test_lava/packed/who/who_info
```

Use `kafl_info.py` and the generated `info` executable to get the address ranges of your fuzzing target:

```
python3 kAFL-Fuzzer/kafl_info.py \
       -kernel /vmlinuz \
       -initrd targets/test_lava/packed/who/who_info_initrd.gz \
       -work_dir /tmp/kafl_workdir/ \
       -forkserver \
       -mem 500
```

Then the packed binary can be fuzzed.

```
python3 kAFL-Fuzzer/kafl_fuzz.py \
       -kernel /vmlinuz \
       -initrd targets/test_lava/packed/who/who_fuzz_initrd.gz \
       -mem 500 \
       -work_dir /tmp/kafl_workdir \
       -seed_dir targets/test_lava/seeds \
       -forkserver \
       -ip0 0x400000-0x47c000 -hammer_jmp_tables -D -redqueen -v -p 2
```

 <a> <img  src="fuzzer.gif"> </a>


### Trophies
* [CVE-2018-12641](https://bugs.launchpad.net/ubuntu/+source/binutils/+bug/1763099) (binutils nm-new)
* [CVE-2018-12697](https://bugs.launchpad.net/ubuntu/+source/binutils/+bug/1763102) (binutils libiberty)
* [CVE-2018-12698](https://bugs.launchpad.net/ubuntu/+source/binutils/+bug/1763102) (binutils libiberty)
* [CVE-2018-12699](https://bugs.launchpad.net/ubuntu/+source/binutils/+bug/1763102) (binutils objdump)
* [CVE-2018-12700](https://bugs.launchpad.net/ubuntu/+source/binutils/+bug/1763102) (binutils objdump)
* [CVE-2018-12928](https://bugs.launchpad.net/ubuntu/+source/linux/+bug/1763384) (linux hfs.ko)
* [CVE-2018-12929](https://bugs.launchpad.net/ubuntu/+source/linux/+bug/1763403) (linux ntfs.ko)
* [CVE-2018-12930](https://bugs.launchpad.net/ubuntu/+source/linux/+bug/1763403) (linux ntfs.ko)
* [CVE-2018-12931](https://bugs.launchpad.net/ubuntu/+source/linux/+bug/1763403) (linux ntfs.ko)
* [CVE-2018-12932](https://bugs.launchpad.net/ubuntu/+source/wine/+bug/1764719) (wine)
* [CVE-2018-12933](https://bugs.launchpad.net/ubuntu/+source/wine/+bug/1764719) (wine)
* [CVE-2018-12934](https://bugs.launchpad.net/ubuntu/+source/binutils/+bug/1763101) (binutils cxxfilt)
* [CVE-2018-12935](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-12935)  (ImageMagick)
* [CVE-2018-14337](https://github.com/mruby/mruby/issues/4062) (mruby)
* [CVE-2018-14566](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-14566) (bash)
* [CVE-2018-14567](https://access.redhat.com/security/cve/cve-2018-14567) (xml2)
* [CVE-2018-16747](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-16747) (fdk-aac)
* [CVE-2018-16748](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-16748) (fdk-aac)
* [CVE-2018-16749](https://github.com/ImageMagick/ImageMagick/issues/1119) (ImageMagick)
* [CVE-2018-16750](https://github.com/ImageMagick/ImageMagick/issues/1118) (ImageMagick)
* [CVE-2018-20116](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20116) (tcpdump)
* [CVE-2018-20117](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20117) (tcpdump)
* [CVE-2018-20118](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20118) (tcpdump)
* [CVE-2018-20119](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20119) (tcpdump)

## License

AGPLv3

**Free Software, Hell Yeah!**
