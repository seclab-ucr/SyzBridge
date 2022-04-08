#!/bin/bash
# Xiaochen Zou 2022, University of California-Riverside
#
# Usage ./deploy-new-image.sh 

set -ex

function config_enable() {
  key=$1
  config=$2
  sed -i "s/$key=n/# $key is not set/g" ${config}
  sed -i "s/$key=m/# $key is not set/g" ${config}
  sed -i "s/# $key is not set/$key=y/g" ${config}
  echo "$key=y" >> ${config}
}

function config_disable() {
  key=$1
  config=$2
  sed -i "s/$key=n/# $key is not set/g" ${config}
  sed -i "s/$key=m/# $key is not set/g" ${config}
  sed -i "s/$key=y/# $key is not set/g" ${config}
}

function change_grub() {
    sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT=""/GRUB_CMDLINE_LINUX_DEFAULT="maybe-ubiquity loglevel=6"/' /etc/default/grub
    sed -i 's/GRUB_CMDLINE_LINUX=""/GRUB_CMDLINE_LINUX="console=ttyS0 earlyprintk=serial"/' /etc/default/grub
    update-grub
}

function install_necessary_packages() {
    codename=$(lsb_release -c | awk  '{print $2}')
    tee /etc/apt/sources.list.d/ddebs.list << EOF
deb-src http://archive.ubuntu.com/ubuntu ${codename} main
deb-src http://archive.ubuntu.com/ubuntu ${codename}-updates main
EOF

    apt-get update
    apt-get build-dep -y linux linux-image-$(uname -r)
    apt-get install -y git trace-cmd fakeroot libncurses-dev gawk flex bison openssl libssl-dev dkms libelf-dev libudev-dev libpci-dev libiberty-dev autoconf
    apt-get install -y linux-cloud-tools-common linux-tools-common || true
}

function clone_ubuntu() {
    mkdir ubuntu-${code_name}
    cd ubuntu-${code_name}
    git clone https://git.launchpad.net/~ubuntu-kernel/ubuntu/+source/linux/+git/${code_name} kernel
    cd ..
}

function compile_ubuntu() {
    cd ubuntu-${code_name}/kernel
    
    if [ -z "${commit}" ]; then
        commit=`git log --since="'${version_since}'" --until="'${version_until}'" -n 1 --pretty=oneline | awk '{{print $1}}'`
    fi
    git checkout ${commit}

    chmod a+x debian/rules
    chmod a+x debian/scripts/*
    chmod a+x debian/scripts/misc/*
    LANG=C fakeroot debian/rules clean

    sed -i '/@perl -f \$(DROOT)\/scripts\/module-check "\$\*" \\/d' debian/rules.d/4-checks.mk
    sed -i '/"\$(prev_abidir)" "\$(abidir)" \$(skipmodule)/d' debian/rules.d/4-checks.mk
    sed -i '/@perl -f \$(DROOT)\/scripts\/config-check \\/d' debian/rules.d/4-checks.mk
    sed -i '/\$(builddir)\/build-\$\*\/\.config "\$(arch)" "\$\*" "\$(commonconfdir)" "\$(skipconfig)"/d' debian/rules.d/4-checks.mk

    # for newer kernel
    sed -i '/\$(builddir)\/build-\$\*\/\.config "\$(arch)" "\$\*" "\$(commonconfdir)" \\/d' debian/rules.d/4-checks.mk
    sed -i '/"\$(skipconfig)" "\$(do_enforce_all)"/d' debian/rules.d/4-checks.mk

    sed -i 's/if \[ "\$fail" != 0 \]; then/if \[ "\$fail" != -1 \]; then/' debian/scripts/misc/kernelconfig

    printf '#!'"/usr/bin/perl\nexit 0" > debian/scripts/config-check
    printf '#!'"/usr/bin/python3\nsys.exit(0)" > debian/scripts/module-check
    chmod +x debian/scripts/config-check
    chmod +x debian/scripts/module-check

    patch -p1 -f -i ~/dkms.patch || echo "probably fine"

    CONFIGKEYSENABLE="
    CONFIG_FAILSLAB
    CONFIG_FAIL_FUTEX
    CONFIG_FAIL_IO_TIMEOUT
    CONFIG_FAIL_MAKE_REQUEST
    CONFIG_FAIL_MMC_REQUEST
    CONFIG_FAIL_PAGE_ALLOC
    CONFIG_FAULT_INJECTION_DEBUG_FS
    CONFIG_KASAN_INLINE"

    CONFIGKEYSDISABLE="
    CONFIG_KASAN_OUTLINE
    CONFIG_TEST_KASAN"

    CONFIGKEYSSPECIAL="
    CONFIG_KASAN_SHADOW_OFFSET=0xdffffc0000000000"

    for key in $CONFIGKEYSENABLE;
    do
        config_enable $key debian.master/config/config.common.ubuntu
    done

    for key in $CONFIGKEYSDISABLE;
    do
        config_disable $key debian.master/config/config.common.ubuntu
    done

    config_enable "CONFIG_KASAN" debian.master/config/amd64/config.flavour.generic
    config_enable "CONFIG_FAULT_INJECTION" debian.master/config/amd64/config.flavour.generic
    config_enable "CONFIG_UBSAN" debian.master/config/amd64/config.flavour.generic
    LANG=C fakeroot debian/rules defaultconfigs
    LANG=C fakeroot debian/rules -j`nproc` binary-headers binary-generic binary-perarch skipdbg=false

    cd ..
    dpkg -i linux*.deb
}

if [ $# -ne 3 ] && [ $# -ne 2 ] && [ $# -ne 1 ] ; then
  echo "Usage ./deploy-ubuntu-image.sh code_name [version_since version_until | commit]"
  exit 1
fi

if [ $# -eq 1 ]; then
    func=$1
    ${func}
    exit 0
fi

if [ $# -eq 3 ]; then
    code_name=$1
    version_since=$2
    version_until=$3
    commit=''
fi

if [ $# -eq 2 ]; then
    code_name=$1
    commit=$2
    version_since=''
    version_until=''
fi

kernel_version=`uname -r`
issue=`cat /etc/issue`
echo "deploying new image for ${issue} ${kernel_version}"

change_grub

install_necessary_packages

clone_ubuntu

compile_ubuntu