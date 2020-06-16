.. _zephyr_agent:

kAFL Hello 
###########

This is a hello world/sample app for fuzzing Zephyr with kAFL.

Building and Running
********************

See quick howto below for how to build this using Zephyr RTOS+SDK.

To compile the fuzzing hello world sample, compile with "KAFL_TEST=y":

.. code-block:: console

   mkdir build; cd build
   cmake ../ -D KAFL_TEST=y''
   make

Test using patched Qemu+KVM to observe hypercalls in Qemu log. Take care that
the handshake and fuzzing loop works, otherwise the fuzzer will misbehave.

.. code-block:: console

   qemu-system-x86_64 -serial mon:stdio -enable-kvm -m 16 -nographic -no-reboot -no-acpi \
                      -kernel build/zephyr/zephyr.elf -no-reboot -no-acpi -D qemu_logfile.log


Start the fuzzer in -kernel mode, using the compiled Zephyr kernel with
integrated fuzzing agent as the payload (will be the argment to 'qemu -kernel').
Currently need to provide fake VM snapshot files to make the parser happy.

The IP range can be determined from zephyr.map and should include the subsystem
you are trying to fuzz. Validate in debug.log that Qemu can successfully extract
the target code range from the VM (first couple lines).

.. code-block:: console

   python kafl_fuzz.py -ip0 0x0000000000102af1-0x000000000010ad52 \
        -mem 16 -extra ' -no-reboot -no-acpi' \
        -kernel targets/zephyr_x86_32/build/zephyr/zephyr.elf \
        -seed_dir seed/kafl_vulntest/ \
        -work_dir /dev/shm/kafl_zephyr \
        --purge -v


Zephyr Quick Setup
##################

Please check the latest online guides for detailed information.

Environment/Dependencies Setup
******************************

https://docs.zephyrproject.org/latest/getting_started/installation_linux.html

.. code-block:: console

   sudo apt-get update
   sudo apt-get upgrade
   sudo apt-get install --no-install-recommends git cmake ninja-build gperf ccache dfu-util \
   device-tree-compiler wget python3-pip python3-setuptools python3-wheel python3-yaml xz-utils file make gcc gcc-multilib

   # missing deps on Ubuntu..?
   sudo apt-get install python3-pyelftools

Note that Zephyr needs a recent cmake. Version 3.13.1 at the time of writing.

Zephyr Getting Started Guide
*****************************

https://docs.zephyrproject.org/latest/getting_started/index.html

.. code-block:: console

   # install west
   pip3 install --user west
   which west || echo "Error: ~/.local/bin not in \$PATH?"

   west init zephyrproject
   cd zephyrproject
   west update

   # fetch python req's
   pip3 install --user -r zephyr/scripts/requirements.txt

   # activate host' toolchain
   cd zephyr
   export ZEPHYR_TOOLCHAIN_VARIANT=host
   source zephyr-env.sh

If you have trouble building the hello world sample, try using the Zephyr SDK:

.. code-block:: console

   wget https://github.com/zephyrproject-rtos/sdk-ng/releases/download/v0.11.2/zephyr-sdk-0.11.2-setup.run
   bash zephyr-sdk-0.11.2-setup.run

   source zephyr-env.sh


# Build and run application in Qemu
***********************************

.. code-block:: console

   # build hello world and attempt to run with host side qemu-86
   west build -b qemu_x86 samples/hello_world
   cd build
   ninja run

   # build kAFL hello world using cmake
   cd path/to/zephyr/agent
   mkdir build; cd build
   cmake ../ -D KAFL_TEST=y
   make

