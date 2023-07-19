# 2. Fuzzing Userspace

In this section we are going to fuzz a userspace program called [`selffuzz.exe`](https://github.com/IntelLabs/kafl.targets/blob/master/windows_x86_64/src/userspace/selffuzz_test.c).

This program contains a small `fuzzme()` function, where two `panic()` calls have been nested into a set of conditionals.

~~~C
void fuzzme(uint8_t* input, int size){
    if (size > 0x11){
        if(input[0] == 'K')
            if(input[1] == '3')
                if(input[2] == 'r')
                    if(input[3] == 'N')
                        if(input[4] == '3')
                            if(input[5] == 'l')
                                if(input[6] == 'A')
                                    if(input[7] == 'F')
                                        if(input[8] == 'L')
                                            if(input[9] == '#')
                                                panic();

        if(input[0] == 'P')
            if(input[1] == 'w')
                if(input[2] == 'n')
                    if(input[3] == 'T')
                        if(input[4] == '0')     
                            if(input[5] == 'w')     
                                if(input[6] == 'n')
                                    if(input[7] == '!')
                                        panic();

    }
};
~~~

:::{Note}
The `panic()` function is simply a wrapper over a call to `HYPERCALL_KAFL_PANIC`.
:::

## Provision the guest VM

To compile and setup the `selffuzz.exe` target binary into the VM, we provide a Makefile and an Ansible playbook that will upload the resulting binary into the guest,
and setup it to be executed during the boot sequence (by creating a symlink into the user `Sartup` folder).

Make sure you are located into the [`windows_x86_64`](https://github.com/IntelLabs/kafl.targets/tree/master/windows_x86_64) folder

~~~shell
# from kAFL root repo
cd kafl/examples/windows_x86_64
~~~

And execute the provisioning userspace target.

~~~shell
make provision_userspace
~~~

Expected output:
~~~shell
make[1]: Entering directory '/home/user/kafl/kafl/examples/windows_x86_64'
mkdir -p bin/{userspace,driver}
x86_64-w64-mingw32-gcc src/userspace/selffuzz_test.c -I ../ -o bin/userspace/selffuzz_test.exe -Wall -mwindows
x86_64-w64-mingw32-gcc src/driver/vuln_test.c -I ../ -o bin/driver/vuln_test.exe -Wall -lntdll -lpsapi
vagrant snapshot restore 'ready_provision'
==> vagrant-kafl-windows: Restoring the snapshot 'ready_provision'...
TARGET_HARNESS='userspace' vagrant provision
==> vagrant-kafl-windows: Running provisioner: host_shell...
[stdout]
PLAY [Setup target] ************************************************************

TASK [Gathering Facts] *********************************************************

[stdout] ok: [192.168.122.168]

TASK [Set default value for target_harness] ************************************

[stdout] skipping: [192.168.122.168]

TASK [Upload binaries] *********************************************************

[stdout] changed: [192.168.122.168]

TASK [Setup userspace target to run at user login] *****************************

[stdout] changed: [192.168.122.168]

TASK [Upload vuln driver sources] **********************************************

[stdout] skipping: [192.168.122.168]

TASK [Compile driver with MSBuild] *********************************************

[stdout] skipping: [192.168.122.168]

TASK [Set service to start vuln_driver.sys at boot] ****************************

[stdout] skipping: [192.168.122.168]

TASK [Set service to start vuln_test to trigger the driver] ********************

[stdout] skipping: [192.168.122.168]

PLAY RECAP *********************************************************************
192.168.122.168            : ok=3    changed=2    unreachable=0    failed=0    skipped=5    rescued=0    ignored=0


vagrant halt
==> vagrant-kafl-windows: Clearing any previously set forwarded ports...
==> vagrant-kafl-windows: Attempting graceful shutdown of VM...
make[1]: Leaving directory '/home/user/kafl/kafl/examples/windows_x86_64'
~~~

## Start Fuzzing

Everything is in place to start fuzzing our target now !

You can review the [`kafl.yaml`](https://github.com/IntelLabs/kafl.targets/blob/master/windows_x86_64/kafl.yaml) where the `qemu_image` parameter has already been configured for you.

Make sure you are running inside the kAFL virtualenv.

To start fuzzing, , and run the `kalf fuzz` command:

~~~shell
# root of kAFL repo
make env
cd kafl/examples/windows_x86_64
(venv) kafl fuzz
~~~

The fuzzer will boot the QEMU Windows image, and the `selffuzz.exe` program should start its execution around 1 minute afterwards.

:::{Note}
For the full command-line reference, please refer to [Fuzzer Configuration](../../reference/fuzzer_configuration.md) page.
:::

➡️ You can start the [kAFL GUI](../../reference/user_interface.md) to watch the campaign progress live in your terminal
