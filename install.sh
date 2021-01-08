#!/bin/bash

#LINUX_VERSION="5.4.55"
LINUX_VERSION="5.7.12"
LINUX_VERSION="5.8.12"
LINUX_URL="https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-${LINUX_VERSION}.tar.xz"

#QEMU_VERSION="4.2.0"
QEMU_VERSION="5.0.0"
QEMU_URL="https://download.qemu.org/qemu-${QEMU_VERSION}.tar.xz"

echo "================================================="
echo "           kAFL auto-magic installer             "
echo "================================================="

checked_download()
{
	filename="$1"
	url="$2"

	if [ ! -f "$filename" ]; then
		echo "[*] Downloading $filename ..."
		wget -O "$filename" "$url"
	fi

	grep $filename sha256sums.lst | sha256sum -c || exit
}

check_gitconfig()
{
	if [ ! "`git config --get user.name`" ] || [ ! "`git config --get user.email`" ]; then
		echo "[-] Error: The installer uses git in order to manage local patches against qemu and linux sources."
   		echo "           Please setup a valid git config in order for this to work:"
		echo
	 	echo " $ git config --global user.name Joe User"
	    echo " $ git config --global user.email joe.user@invalid.local"
		echo
		exit 1
	fi
}

system_check()
{
	echo
	echo "[*] Performing basic sanity checks..."

	if [ ! "`uname -s`" = "Linux" ]; then
		echo "[-] Error: KVM-PT is supported only on Linux ..."
		exit 1
	fi

	grep -q ^flags.*intel_pt /proc/cpuinfo
	if [ $? -ne 0 ]; then
		echo "According to /proc/cpuinfo this system has no intel_pt."
		exit 1
	fi

dist_id="$(lsb_release -si)"
	if [ "$dist_id" != "Debian" -a "$dist_id" != "Ubuntu" ]; then
		echo "[-] Error: This installer was tested using recent Debian and Ubuntu."
		echo
		echo "Other recent Linux distributions will generally work as well but"
		echo "the installer will not be able to resolve the required dependencies."
		echo
		echo "It is recommended to abort the installer and instead follow this"
		echo "script by hand, resolving any build/runtime errors as they come up."
		echo
		echo "Press [Ctrl-c] to abort or [Return] to continue.."
		read
	fi

	for i in dpkg apt-get sudo; do
		T=`which "$i" 2>/dev/null`
		if [ "$T" = "" ]; then
			echo "[-] Error: '$i' not found, please install first."
			exit 1
		fi
	done

	check_gitconfig
}

system_deps()
{
	echo
	echo "[*] Installing essentials tools ..."
	sudo apt-get install git make gcc bc libssl-dev pax-utils libelf-dev \
		libgraphviz-dev gnuplot ruby libgtk-3-dev libc6-dev flex bison \
		python3 python3-pip python3-all-dev python3-setuptools python3-wheel -y

	echo "[*] Installing build dependencies for QEMU ..."
	sudo apt-get build-dep qemu-system-x86 -y
	# libcapstone is an optional qemu feature but a hard requirement for kAFL
	sudo apt-get install libcapstone-dev libcapstone3

	echo "[*] Installing kAFL python dependencies ..."
	pip3 install --user mmh3 lz4 psutil fastrand ipdb inotify msgpack toposort pygraphviz pgrep tqdm six python-dateutil
}

build_qemu()
{
	echo
	echo "[*] Building Qemu ${QEMU_VERSION} ..."

	check_gitconfig

	if [ -d "qemu-${QEMU_VERSION}" ]; then
		echo "[*] Folder exists, skipping download + patching..."
		pushd "qemu-${QEMU_VERSION}"
	else
		checked_download "qemu-${QEMU_VERSION}.tar.xz" "$QEMU_URL"
		tar xf "qemu-${QEMU_VERSION}.tar.xz" || exit
		pushd "qemu-${QEMU_VERSION}"
		git init
		git add .
		git commit -m "vanilla qemu-${QEMU_VERSION}"

		echo "[*] Applying QEMU patches ..."
		git am ../patches/qemu/v${QEMU_VERSION}/00*.patch
	fi

	echo "[*] Building ..."
	echo "-------------------------------------------------"
	./configure --target-list=i386-softmmu,x86_64-softmmu --enable-vnc --enable-gtk --enable-pt --enable-redqueen --disable-werror
	make -j $jobs
	echo
	echo "-------------------------------------------------"
	echo "Qemu build should be done now. Note that you do not have to install this Qemu build into the system."
	echo "Just update kAFL-Fuzzer/kafl.ini to point it in the proper direction:"
	echo
	echo    QEMU_KAFL_LOCATION = qemu-${QEMU_VERSION}/x86_64-softmmu/qemu-system-x86_64
	echo

	popd
}

build_linux()
{
	echo
	echo "[*] Building Linux $LINUX_VERSION ..."

	check_gitconfig

	if [ -d linux-${LINUX_VERSION} ]; then
		echo "[*] Folder exists, assume it is already patched.."
		pushd "linux-${LINUX_VERSION}"
	else
		checked_download "linux-${LINUX_VERSION}.tar.xz" "$LINUX_URL"
		tar xf "linux-${LINUX_VERSION}.tar.xz" || exit
		pushd "linux-${LINUX_VERSION}" || exit
		git init
		git add .
		git commit -m "vanilla linux-${LINUX_VERSION}"
		echo "[*] Applying Linux patches ..."
		BASE_VERSION=$(echo $LINUX_VERSION|sed "s/\.[0-9]*$//")
		git am ../patches/kvm/v${BASE_VERSION}/*.patch
	fi

	echo "[*] Building ..."
	echo "-------------------------------------------------"
   	# use current/system config as base, but limit modules to actual used..
	yes ""|make oldconfig
	#make localmodconfig
	./scripts/config --set-str CONFIG_LOCALVERSION "-kAFL" --set-val CONFIG_KVM_VMX_PT y
	./scripts/config --set-str CONFIG_SYSTEM_TRUSTED_KEYS ""
	make -j $jobs
	echo "-------------------------------------------------"

	popd
}

build_radamsa()
{
	echo
	echo "[*] Building radamsa..."

	check_gitconfig

	if [ -d radamsa ]; then
		echo "[*] Folder exists, skipping download..."
	else
		git clone https://gitlab.com/akihe/radamsa.git radamsa
	fi

	echo "[*] Building ..."
	make -j $jobs -C radamsa
}

build_targets()
{
	echo
	echo "[*] Building Target components ..."
	pushd targets
	bash compile.sh
	popd
}

system_perms()
{
	echo
	echo "[*] Fix permissions for user access to /dev/kvm..."
	echo
	sudo groupmod kvm
	if [ $? -ne 0 ]; then
		echo "Creating group kvm for user $USER to access /dev/kvm.."

		echo "KERNEL==\"kvm\", GROUP=\"kvm\"" | sudo -Eu root tee /etc/udev/rules.d/40-permissions.rules > /dev/null
		sudo groupadd kvm
		sudo usermod -a -G kvm $USER
		sudo root service udev restart
	else
		id|grep -q '(kvm)'
		if [ $? -eq 0 ]; then
			echo "KVM already seems to be setup for user $USER, skipping.."
		else
			echo "Group KVM already exists, adding this user $USER.."
			sudo usermod -a -G kvm $USER
		fi
	fi
}

print_help()
{
	echo
	echo "Usage: ./install <action>"
	echo
	echo "Perform complete installation or limit to individual action:"
	echo
	echo " check   - check for basic requirements"
	echo " deps    - install dependencies"
	echo " qemu    - download and build modified qemu"
	echo " linux   - download and build modified linux kernel"
	echo " perms   - create kvm group and add user <$USER> for /dev/kvm access"
	echo " radamsa - download and build radamsa plugin"
	echo
	echo " all     - perform all of the above."
	echo
}

install_note()
{
	echo "To install the patched kernel, try something like this:"
	echo
	echo "  $ cd linux-${LINUX_VERSION}"
	echo "  $ # optionally set 'MODULES=dep' in /etc/initramfs-tools/initramfs.conf"
	echo "  $ sudo make INSTALL_MOD_STRIP=1 modules_install"
	echo "  $ sudo make install"
	echo
}

####################################
# main()
####################################

# Auto-scale building with number of CPUs. Override with ./install -j N <action>
jobs=$(nproc)
[ "$1" = "-j" ] && [ -n $2 ] && [ $2 -gt 0 ] && jobs=$2 && shift 2
#echo "Detected $(nproc) cores, building with -j $jobs..."

case $1 in
	"check")
		system_check
		;;
	"deps")
		system_check
		system_deps
		;;
	"radamsa")
		build_radamsa
		;;
	"qemu")
		build_qemu
		;;
	"linux")
		build_linux
		;;
	"targets")
		build_targets
		;;
	"perms")
		system_perms
		;;
	"all")
		system_deps
		build_qemu
		build_linux
		build_radamsa
		system_perms
		build_targets
		;;
	"note")
		install_note
		;;
	*)
		print_help
		exit
		;;
esac

echo
echo "[*] All done."
echo

case $1 in
	"linux"|"all")
		install_note
		;;
esac

exit
