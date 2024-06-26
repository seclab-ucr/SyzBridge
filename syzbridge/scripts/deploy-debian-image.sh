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

function prepare_script() {
cat << EOF > /etc/systemd/system/dhclient.service
[Unit]
Description=Start dhclinet

[Service]
ExecStart=/sbin/dhclient
Type=oneshot
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

    chmod 644 /etc/systemd/system/dhclient.service
    # Disable auto update
    rm /etc/apt/apt.conf.d/20auto-upgrades || true
    cat << EOF > /etc/apt/apt.conf.d/20auto-upgrades
APT::Periodic::Update-Package-Lists "0";
APT::Periodic::Download-Upgradeable-Packages "0";
APT::Periodic::AutocleanInterval "0";
APT::Periodic::Unattended-Upgrade "0";
EOF
    systemctl enable dhclient.service
}

function change_grub() {
    if [ ! -f ~/.stamp/CHANGE_GRUB ]; then
        sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT="quiet"/GRUB_CMDLINE_LINUX_DEFAULT="quiet maybe-ubiquity loglevel=6"/' /etc/default/grub
        sed -i 's/GRUB_CMDLINE_LINUX=""/GRUB_CMDLINE_LINUX="nokaslr console=ttyS0 earlyprintk=serial"/' /etc/default/grub
        update-grub
        touch ~/.stamp/CHANGE_GRUB
    fi
}

function install_necessary_packages() {
    if [ ! -f ~/.stamp/INSTALL_PACKAGES ]; then
        if [ "${code_name}" == "bullseye" ]; then
            sed -i -e 's/deb.debian.org/archive.debian.org/g' \
                -e 's/ftp.us.debian.org/archive.debian.org/g' \
                -e 's|security.debian.org|archive.debian.org/|g' \
                -e '/bullseye-updates/d' /etc/apt/sources.list
        fi
        apt-get update
        apt-get install -y git trace-cmd psmisc build-essential devscripts fakeroot libncurses-dev gawk flex bison openssl libssl-dev dkms libelf-dev libudev-dev libpci-dev libiberty-dev autoconf gcc-multilib libc6-dev-i386
        apt-get build-dep -y linux

        systemctl disable hv-kvp-daemon.service || true

        useradd -m syzbridge || true
        touch ~/.stamp/INSTALL_PACKAGES
    fi
}

function get_debian() {
    if [ ! -f ~/.stamp/GET_DEBIAN ]; then
        mkdir debian-${code_name} || (rm -rf debian-${code_name} && mkdir debian-${code_name})
        cd debian-${code_name}
        dget -u ${dsc_url}
        cd ..
        touch ~/.stamp/GET_DEBIAN
    fi
}

function compile_debian() {
    if [ ! -f ~/.stamp/COMPILE_DEBIAN ]; then
        cd ~/debian-${code_name}/linux-${kernel_version}
        
        cp /boot/config-`uname -r` .config

        CONFIGKEYSENABLE=""
        CONFIGKEYSDISABLE="MODULE_SIG"
        if [ $((enable_feature%2)) == 1 ]; then
            CONFIGKEYSENABLE="KASAN_INLINE
            KASAN
            ${CONFIGKEYSENABLE}"

            CONFIGKEYSDISABLE="KASAN_OUTLINE
            TEST_KASAN
            ${CONFIGKEYSDISABLE}"
        fi
        enable_feature=$((enable_feature>>1))

        if [ $((enable_feature%2)) == 1 ]; then
            CONFIGKEYSENABLE="UBSAN
            ${CONFIGKEYSENABLE}"
        fi
        enable_feature=$((enable_feature>>1))

        if [ $((enable_feature%2)) == 1 ]; then
            CONFIGKEYSENABLE="FAILSLAB
            FAIL_FUTEX
            FAIL_IO_TIMEOUT
            FAIL_MAKE_REQUEST
            FAIL_MMC_REQUEST
            FAIL_PAGE_ALLOC
            FAULT_INJECTION_DEBUG_FS
            FAULT_INJECTION
            ${CONFIGKEYSENABLE}"
        fi
        enable_feature=$((enable_feature>>1))

        if [ $((enable_feature%2)) == 1 ]; then
            CONFIGKEYSENABLE="CONFIG_DEBUG_DEVRES
            CONFIG_DEBUG_INFO
            CONFIG_DEBUG_INFO_BTF
            CONFIG_DEBUG_INFO_BTF_MODULES
            CONFIG_DEBUG_FS
            CONFIG_DEBUG_KERNEL
            CONFIG_DEBUG_MISC
            CONFIG_DEBUG_OBJECTS
            CONFIG_DEBUG_OBJECTS_FREE
            CONFIG_DEBUG_OBJECTS_TIMERS
            CONFIG_DEBUG_OBJECTS_WORK
            CONFIG_DEBUG_OBJECTS_RCU_HEAD
            CONFIG_DEBUG_RT_MUTEXES
            CONFIG_DEBUG_SPINLOCK
            CONFIG_DEBUG_MUTEXES
            CONFIG_DEBUG_LIST
            CONFIG_DEBUG_PLIST
            CONFIG_DEBUG_SG
            CONFIG_DEBUG_NOTIFIERS
            CONFIG_DEBUG_CREDENTIALS
            ${CONFIGKEYSENABLE}"
        fi
        enable_feature=$((enable_feature>>1))

        for key in $CONFIGKEYSENABLE;
        do
            scripts/config --enable $key
        done

        for key in $CONFIGKEYSDISABLE;
        do
            scripts/config --disable $key
        done

        scripts/config --set-str SYSTEM_TRUSTED_KEYS ""

        make olddefconfig
        make bindeb-pkg -j`nproc`
        mv vmlinux vmlinux.bk
        make clean
        mv vmlinux.bk vmlinux

        cd ..
        dpkg -i linux*.deb
        touch ~/.stamp/COMPILE_DEBIAN
    fi
}

function archive_kernel() {
    if [ ! -f ~/.stamp/ARCHIVE_KERNEL ]; then
        cd ~/debian-${code_name}/
        
        cp linux-${kernel_version}/.config linux-${kernel_version}/config
        cd linux-${kernel_version}
        tar -czf debian.tar.gz ./*
        mv debian.tar.gz /tmp
        touch ~/.stamp/ARCHIVE_KERNEL
    fi
}

if [ $# -ne 3 ]; then
  echo "Usage ./deploy-ubuntu-image.sh dsc_url kernel_version enable_feature"
  exit 1
fi

kernel_version=`uname -r`
kernel_major_version=`uname -r | cut -d- -f1`
kernel_minor_version=`uname -r | cut -d- -f2`
issue=`cat /etc/issue`
code_name=$(lsb_release -c | awk  '{print $2}')

if [ $# -eq 3 ]; then
    dsc_url=$1
    kernel_version=$2
    enable_feature=$3
fi

echo "deploying new image for ${issue} ${kernel_version}"
mkdir ~/.stamp || true

prepare_script

change_grub

install_necessary_packages

get_debian

compile_debian

archive_kernel