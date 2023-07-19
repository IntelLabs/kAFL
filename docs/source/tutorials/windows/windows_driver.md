# 3. Fuzzing a Driver

In this section we are going to fuzz a [vulnerable Windows driver](https://github.com/IntelLabs/kafl.targets/blob/master/windows_x86_64/src/kafl_vulnerable_driver/driver.c) built for the purpose of this tutorial.

It contains a `CrashMe()` function that contains 2 conditional paths that lead to a crash:

~~~C
NTSTATUS crashMe(IN PIO_STACK_LOCATION IrpStack){
    SIZE_T size = 0;
    PCHAR userBuffer = NULL;

    userBuffer = IrpStack->Parameters.DeviceIoControl.Type3InputBuffer;
    size = IrpStack->Parameters.DeviceIoControl.InputBufferLength;

    if (size < 0xe){
        return STATUS_SUCCESS;
    }

    if (userBuffer[0] == 'P'){
        if (userBuffer[1] == 'w'){
            if (userBuffer[2] == 'n'){
                if (userBuffer[3] == 'T'){
                    if (userBuffer[4] == 'o'){
                        if (userBuffer[5] == 'w'){
                            if (userBuffer[6] == 'n'){
                            DbgPrint("[+] KAFL vuln drv -- SETEIP");
                            /* hell yeah */
                            ((VOID(*)())0x0)();
                            }
                        }
                    }
                }
            }
        }
    }

    if (userBuffer[0] == 'w'){
        DbgPrint("[+] KAFL vuln drv -- ONE");
        if (userBuffer[1] == '0'){
            DbgPrint("[+] KAFL vuln drv -- TWO");
            if (userBuffer[2] == '0'){
                DbgPrint("[+] KAFL vuln drv -- THREE");
                if (userBuffer[3] == 't'){
                    DbgPrint("[+] KAFL vuln drv -- CRASH");
                    size = *((PSIZE_T)(0x0));
                }
            }
        }
    }

    return STATUS_SUCCESS;
}
~~~

This function will be called everytime the driver receives an `IRP_MJ_DEVICE_CONTROL` with `IOCTL_KAFL_INPUT`:

~~~C
switch(irpStack->MajorFunction){
    case IRP_MJ_DEVICE_CONTROL:
        ioctl = irpStack->Parameters.DeviceIoControl.IoControlCode;
        switch(ioctl){
            case IOCTL_KAFL_INPUT:
                DbgPrint("[+] KAFL vuln drv -- crash attempt\n");
                pIrp->IoStatus.Status = crashMe(irpStack);
                break;
~~~

We are going to trigger this function by feeding the driver a kAFL buffer from userspace via another program: [vuln_test.c](https://github.com/IntelLabs/kafl.targets/blob/master/windows_x86_64/src/driver/vuln_test.c)

Excerpt from `vuln_test.c`:

~~~c
// Snapshot here
kAFL_hypercall(HYPERCALL_KAFL_NEXT_PAYLOAD, 0);

/* request new payload (*blocking*) */
kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0); 

/* kernel fuzzing */
DeviceIoControl(kafl_vuln_handle,
    IOCTL_KAFL_INPUT,
    (LPVOID)(payload_buffer->data),
    (DWORD)payload_buffer->size,
    NULL,
    0,
    NULL,
    NULL
);

/* inform fuzzer about finished fuzzing iteration */
// Will reset back to start of snapshot here
kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
~~~


## Provision the guest VM

To compile and setup both the  `kAFLvulnerabledriver.sys` and `vuln_test.exe` target binaries into the VM, we provide a Makefile and an Ansible playbook that will upload the resulting binary into the guest, and setup it to be executed during the boot sequence (by creating a symlink into the user `Sartup` folder).

Make sure you are located into the [`windows_x86_64`](https://github.com/IntelLabs/kafl.targets/tree/master/windows_x86_64) folder

~~~shell
# from kAFL root repo
cd kafl/examples/windows_x86_64
~~~

And execute the provisioning userspace target.

~~~shell
make provision_driver
~~~

Expected output:
~~~shell
make[1]: Entering directory '/home/user/kafl/kafl/examples/windows_x86_64'
mkdir -p bin/{userspace,driver}
x86_64-w64-mingw32-gcc src/userspace/selffuzz_test.c -I ../ -o bin/userspace/selffuzz_test.exe -Wall -mwindows
x86_64-w64-mingw32-gcc src/driver/vuln_test.c -I ../ -o bin/driver/vuln_test.exe -Wall -lntdll -lpsapi
vagrant snapshot restore 'ready_provision'
==> vagrant-kafl-windows: Restoring the snapshot 'ready_provision'...
TARGET_HARNESS='driver' vagrant provision
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

[stdout] skipping: [192.168.122.168]

TASK [Upload vuln driver sources] **********************************************

[stdout] changed: [192.168.122.168]

TASK [Compile driver with MSBuild] *********************************************

[stdout] changed: [192.168.122.168]

TASK [Set service to start vuln_driver.sys at boot] ****************************

[stdout] changed: [192.168.122.168]

TASK [Set service to start vuln_test to trigger the driver] ********************

[stdout] changed: [192.168.122.168]

PLAY RECAP *********************************************************************
192.168.122.168            : ok=6    changed=5    unreachable=0    failed=0    skipped=2    rescued=0    ignored=0


vagrant halt
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

The fuzzer will boot the QEMU Windows image, and the `vuln_test.exe` program should start its execution around 1 minute afterwards.

:::{Note}
For the full command-line reference, please refer to [Fuzzer Configuration](../../reference/fuzzer_configuration.md) page.
:::

➡️ You can start the [kAFL GUI](../../reference/user_interface.md) to watch the campaign progress live in your terminal
