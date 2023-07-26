# kAFL Workdir


The `workdir` is used by kAFL to accumulate results and communicate with QEMU
and other processes. It is the primary location for inspecting the status of
a previous or still running kAFL session. Also, any post-processing steps such
as triage or coverage analysis typically builds up on an existing workdir.

## Usage Conventions

Due to the frequent use by addition tools and scripts, the kAFL deployment
defines a default workdir location in `env.sh`. It is recommended to use
this `$KAFL_WORKDIR` and related environment variables rather than hard-coding
paths in the various tools and helper scripts.

The default value of `$KAFL_WORKDIR` points to a location in `/dev/shm/`.  This
means the workdir is only stored in RAM, which tends to result in better
performance and avoids unnecessary disk I/O during prototyping. To keep the
results of a campaign, exit the fuzzer and copy the entire workdir to a more
permanent location.

## Configuration Options

The target `workdir` is set using the commandline argument [`--work-dir`](fuzzer_configuration.md#work_dir) or
corresponding configuration file entry `work_dir`. By default, it is expected to
be a non-existing path that will be populated with several special files and
folders on startup.

The argument [`--purge`](fuzzer_configuration.md#purge) can be supplied to override this safety and
purge a previously existing workdir on startup. This is mainly useful when
developing or testing a harness.

The argument [`--resume`](fuzzer_configuration.md#resume) can be supplied to the opposite effect - the workdir
will not be deleted and any Qemu instances will be reloaded from the existing
snapshot. This is currently only supported for triage or coverage
analysis. The fuzzer itself does not yet support resuming from
an existing workdir, but you can use one or more previously discovered
input corpuses as seeds ([`--seed-dir`](fuzzer_configuration.md#seed_dir)).


## Detailed Content

Workdir content is a mix of status/output and program-internal IPC/SHM files.
They are sorted here by relevance. The `kafl mcat` tool can be used to view
msgpack encoded files.

Note that some files may not exist, e.g. log files are only created on first
write. Also many of the internal IPC/SHM files will be deleted on exit.

    $ tree $KAFL_WORKDIR/
    │
    │ # fuzzer status, can be used by kafl fuzz, kafl plot, gnuplot...
    │
    ├── config.yaml                  - config dump by kafl fuzz (YAML)
    ├── stats                        - aggregated status (msgpack)
    ├── stats.csv                    - aggregated status over time (csv table)
    ├── worker_stats_N               - worker N status (msgpack)
    │
    │ # debug and crash logs
    │
    ├── hprintf_NN.log               - hprintf log for Worker N (--log-hprintf)
    ├── serial_NN.log                - Qemu serial log for Worker N
    ├── kafl_fuzzer.log              - kAFL Fuzzer python log (--log)
    ├── logs/                        - hprintf excerpts from irregular exits,
    │   ├── crash_XXXXXX.log           tagged with truncated hash of execution bitmap
    │   ├── kasan_XXXXXX.log
    │   └── timeo_XXXXXX.log
    │
    ├── imports/                     - copy files here to evaluate them as input, also
    │                                  used for initial seed import (--seed-dir)
    │
    │ # campaign results
    │
    ├── dump/                        - location for guest uploads (HYPERCALL_KAFL_DUMP_FILE)
    ├── funky/                       - location for non-deterministic payloads (--funky)
    ├── traces/                      - location for PT traces (see kafl cov and --trace)
    │
    ├── corpus/                      - corpus of discovered payloads by Qemu exec result
    │   ├── crash/
    │   │   └── payload_AAAAA          => HYPERCALL_KAFL_PANIC
    │   ├── kasan/
    │   │   └── payload_BBBBB          => HYPERCALL_KAFL_KASAN
    │   ├── regular/
    │   │   └── payload_CCCCC          => HYPERCALL_KAFL_RELEASE
    │   └── timeout/
    │       └── payload_DDDDD          => timeout (catched by host side)
    │
    ├── metadata/                    - meta info for each corpus payload (msgpack)
    │   ├── node_AAAAA
    │   ├── node_BBBBB
    │   ├── node_CCCCC
    │   └── node_DDDDD
    │
    │ # (not as interesting files)
    │
    ├── kafl_socket                  - socket between kAFL manager and workers
    ├── interface_N                  - socket between kAFL worker N and Qemu N
    ├── payload_N                    - Worker/Qemu payload SHM
    ├── aux_buffer_N                 - Worker/Qemu aux_buffer SHM
    ├── bitmap_N                     - Worker/Qemu main bitmap SHM
    ├── ijon_N                       - Worker/Qemu ijon bitmap SHM
    ├── radamsa_N/                   - IPC for radamsa integration
    ├── redqueen_workdir_N/          - IPC for redqueen integration
    │
    ├── page_cache.addr              - Shared guest page cache for PT decode
    ├── page_cache.dump
    ├── page_cache.lock
    │
    ├── bitmaps/                     - global feedback bitmaps by exec result
    │   ├── main_crash_bitmap
    │   ├── main_kasan_bitmap
    │   ├── main_normal_bitmap
    │   └── main_timeout_bitmap
    │
    └── snapshot/                    - Nyx snapshot files
        ├── fast_snapshot.mem_dump
        ├── fast_snapshot.mem_meta
        ├── fast_snapshot.qemu_state
        ├── fs_cache.meta
        ├── global.state
        ├── INFO.txt
        └── ready.lock
