.. _zephyr_agent:

Zephyr Fuzzing
##############

This folder contains example agents and helper scripts to get started with
fuzzing Zephyr with kAFL.

All of the below steps are captured in the `compile.sh` helper script, so the
below notes are only relevant for context, in case the script does not work or
if you want to run your own RTOS/FW image in kAFL.

All scripts are meant to be called from the kAFL root:

.. code-block:: console

    ./targets/zephyr_x86_32/compile.sh zephyr
    ./targets/zephyr_x86_32/compile.sh build TEST
    ./targets/zephyr_x86_32/compile.sh run -v -redqueen -p 2

All status and output is written to a temporary work dir in /dev/shm/kafl_zephyr by default.
Follow the main kAFL Readme to view the status in a separate terminal:

.. code-block:: console
    
   python3 kAFL-Fuzzer/kafl_gui.py /dev/shm/kafl_zephyr
   python3 kAFL-Fuzzer/kafl_plot.py /dev/shm/kafl_zephyr
   gnuplot -c ~/kafl/tools/stats.plot $workdir/stats.csv



Zephyr RTOS + SDK Install
#########################

Quick steps captured below, check the latest Zephyr guides for detailed
information.

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


Launching Zephyr RTOS
######################

To launch Zephyr you need to build a particular application which will be run as
the main thread. Zephyr will not do anything useful if that application is
missing.

# Build and run application in Qemu
***********************************

Start building the Zephyr hello world. We need to have this running in a qemu
environment that is compatible with the later kAFL Qemu setup. In particular,
this means our target app should work with -enable-kvm. Also note the required
RAM and any other dependencies at this point.

.. code-block:: console

   # build hello world and attempt to run with host side qemu-86
   west build -b qemu_x86 samples/hello_world
   cd build
   ninja run

   ps aux|grep qemu # note commandline

   # confirm it running with KVM and minimum other parameters
   qemu -kernel zephyr.elf -enable-kvm -m 16 [...]


# Build and run Zephyr-based kAFL Agent
***************************************

To fuzz Zephyr or one of its components, we need to integrate a kAFL agent into
the guest VM. The agent communicates with kAFL to receive a fuzz input and
deliver it to the desired test target.

We provide two examples: The `TEST` application implements its own target_test()
function which contains known bugs. The fuzzer will quickly find the inputs that
cause this function to crash. The `JSON` application calls the json parser of
Zephyr to process the fuzzer input, thus fuzzing the json parser.

.. code-block:: console

   cd path/to/zephyr/agent
   mkdir build; cd build
   cmake ../ -D KAFL_TEST=y''
   make

Test the build using the patched Qemu+KVM. We expect it to fail on the
hypercalls since the kAFL frontend is missing. However, we can confirm at this
point that the agent actually starts and attempts to connect to kAFL as
expected. We can also identify the minimum qemu commandline required to boot
Zephyr and potentially adjust the configuration used by kAFL.

.. code-block:: console

   qemu-system-x86_64 -serial mon:stdio -enable-kvm -m 16 -nographic -no-reboot -no-acpi \
                      -kernel build/zephyr/zephyr.elf -no-reboot -no-acpi -D qemu_logfile.log


Start the fuzzer in -kernel mode, using the compiled Zephyr kernel with
integrated fuzzing agent as the payload (will be the argment to 'qemu -kernel').
Currently need to provide fake VM snapshot files to make the parser happy.

The IP range can be determined from `build/zephyr.map` and should include the subsystem
you are trying to fuzz. Typically we can just use the entire `.text` segment here
since Zephyr strips any unnecessary functionality at build time and will not
have any undesired background activity outside our fuzzing loop.

.. code-block:: console

   python kafl_fuzz.py -ip0 0x0000000000102af1-0x000000000010ad52 \
        -mem 16 -extra ' -no-reboot -no-acpi' \
        -kernel targets/zephyr_x86_32/build/zephyr/zephyr.elf \
        -seed_dir seed/kafl_vulntest/ \
        -work_dir /dev/shm/kafl_zephyr \
        --purge -v


