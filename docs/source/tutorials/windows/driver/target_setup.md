# Provision the guest VM

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

At this stage, the `kAFLvulnerabledriver` and `vuln_test` have been compiled and installed into the VM, ready to be executed at next boot !
