# Generate a .env file to be sourced by pipenv
# If you don't use west, customize .env for your own repo locations.

if ! which west > /dev/null; then
	echo "Could not find west. Run this script from within the west workspace and python venv."
	exit -1
fi

if ! west list manifest > /dev/null; then
	echo "Failed to locate West manifest - not initialized?"
	exit -1
fi

# silence missing Zephyr install?
if ! west list zephyr > /dev/null 2>&1; then
   if ! west config zephyr.base > /dev/null; then
	   west config zephyr.base not-using-zephyr
   fi
fi

echo KAFL_ROOT=$(west list -f {abspath} kafl)
echo QEMU_ROOT=$(west list -f {abspath} qemu)
echo LIBXDC_ROOT=$(west list -f {abspath} libxdc)
echo CAPSTONE_ROOT=$(west list -f {abspath} capstone)
echo RADAMSA_ROOT=$(west list -f {abspath} radamsa)

# default kAFL workdir + config
echo KAFL_CONFIG_FILE=$KAFL_ROOT/kafl.yaml
echo KAFL_WORKDIR=/dev/shm/${USER}_tdfl
