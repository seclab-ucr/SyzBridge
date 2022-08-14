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
    cat << EOF > replace-check-mk
#!/usr/bin/python3

import sys

src = sys.argv[1]
dst = sys.argv[2]

skip = -1
new_text = []
with open(src, "r") as f:
    texts = f.readlines()
    for line in texts:
        if "module-check-%: " in line or \\
                "config-prepare-check-%: " in line:
            skip = 2
        if line == "\n":
            skip = -1
        if skip != 0:
            new_text.append(line)
            skip -= 1

with open(dst, "w") as f:
    f.writelines(new_text)
EOF

    chmod +x replace-check-mk

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
    systemctl enable dhclient.service
}

function change_grub() {
    if [ ! -f ~/.stamp/CHANGE_GRUB ]; then
        sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT=""/GRUB_CMDLINE_LINUX_DEFAULT="maybe-ubiquity loglevel=6"/' /etc/default/grub
        sed -i 's/GRUB_CMDLINE_LINUX=""/GRUB_CMDLINE_LINUX="nokaslr console=ttyS0 earlyprintk=serial"/' /etc/default/grub
        update-grub
        touch ~/.stamp/CHANGE_GRUB
    fi
}

function install_necessary_packages() {
    if [ ! -f ~/.stamp/INSTALL_PACKAGES ]; then
        tee /etc/apt/sources.list.d/ddebs.list << EOF
deb-src http://archive.ubuntu.com/ubuntu ${code_name} main
deb-src http://archive.ubuntu.com/ubuntu ${code_name}-updates main
EOF

        apt-get update
        apt-get build-dep -y linux linux-image-$(uname -r)
        apt-get install -y git trace-cmd psmisc fakeroot libncurses-dev gawk flex bison openssl libssl-dev dkms libelf-dev libudev-dev libpci-dev libiberty-dev autoconf gcc-multilib
        apt-get install -y linux-cloud-tools-common linux-tools-common || true

        systemctl disable hv-kvp-daemon.service

        useradd -m syzmorph || true
        touch ~/.stamp/INSTALL_PACKAGES
    fi
}

function clone_ubuntu() {
    if [ ! -f ~/.stamp/CLONE_UBUNTU ]; then
        mkdir ubuntu-${code_name} || (rm -rf ubuntu-${code_name} && mkdir ubuntu-${code_name})
        cd ubuntu-${code_name}
        git config --global http.sslVerify "false"
        git clone https://git.launchpad.net/~ubuntu-kernel/ubuntu/+source/linux/+git/${code_name} kernel
        cd ..
        touch ~/.stamp/CLONE_UBUNTU
    fi
}

function compile_ubuntu() {
    if [ ! -f ~/.stamp/COMPILE_UBUNTU ]; then
        cd ~/ubuntu-${code_name}/kernel
        
        if [ -z "${commit}" ]; then
            tag_name=''
            git log --tags --since="'${version_since}'" --until="'${version_until}'" -n 20 --pretty=oneline --simplify-by-decoration | awk '{{print $3}}' | \
                ( while read -r line; do \
                    if [[ "${line}" == "Ubuntu-${kernel_major_version}"* ]]; then \
                        tag_name=${line}; \
                        break; \
                    fi \
                done
            commit=`git log --tags --since="'${version_since}'" --until="'${version_until}'" -n 20 --pretty=oneline --simplify-by-decoration | grep ${tag_name} | awk '{{print $1}}'`
            if [ -z "${commit}" ]; then
                echo "Cannot find a commit between ${version_since} and ${version_until}"
                exit 2
            fi
            tag=`git describe ${commit}`
            echo "Switch to tag ${tag}"
            git checkout ${tag})
        else
            tag=`git describe ${commit}`

            echo "Switch to tag ${tag}"
            git checkout ${tag}
        fi

        chmod a+x debian/rules
        chmod a+x debian/scripts/*
        chmod a+x debian/scripts/misc/*
        LANG=C fakeroot debian/rules clean

        rm debian/rules.d/4-checks-new.mk || true
        
        ~/replace-check-mk debian/rules.d/4-checks.mk debian/rules.d/4-checks-new.mk

        mv debian/rules.d/4-checks.mk debian/rules.d/4-checks-new-old.mk
        mv debian/rules.d/4-checks-new.mk debian/rules.d/4-checks.mk

        sed -i 's/if \[ "\$fail" != 0 \]; then/if \[ "\$fail" != -1 \]; then/' debian/scripts/misc/kernelconfig

        #printf '#!'"/usr/bin/perl\nexit 0" > debian/scripts/config-check
        #printf '#!'"/usr/bin/python3\nsys.exit(0)" > debian/scripts/module-check
        #chmod +x debian/scripts/config-check
        #chmod +x debian/scripts/module-check

        patch -p1 -f -i ~/dkms.patch || echo "probably fine"

        CONFIGKEYSENABLE=""
        CONFIGKEYSDISABLE=""
        CONFIGKEYSSPECIAL=""
        if [ $((enable_feature%2)) == 1 ]; then
            config_enable "CONFIG_KASAN" debian.master/config/amd64/config.flavour.generic
            CONFIGKEYSENABLE="CONFIG_KASAN_INLINE
            ${CONFIGKEYSENABLE}"

            CONFIGKEYSDISABLE="CONFIG_KASAN_OUTLINE
            CONFIG_TEST_KASAN
            ${CONFIGKEYSDISABLE}"

            CONFIGKEYSSPECIAL="CONFIG_KASAN_SHADOW_OFFSET=0xdffffc0000000000
            ${CONFIGKEYSSPECIAL}"
        fi
        enable_feature=$((enable_feature>>1))

        if [ $((enable_feature%2)) == 1 ]; then
            config_enable "CONFIG_UBSAN" debian.master/config/amd64/config.flavour.generic
        fi
        enable_feature=$((enable_feature>>1))

        if [ $((enable_feature%2)) == 1 ]; then
            config_enable "CONFIG_FAULT_INJECTION" debian.master/config/amd64/config.flavour.generic
            CONFIGKEYSENABLE="CONFIG_FAILSLAB
            CONFIG_FAIL_FUTEX
            CONFIG_FAIL_IO_TIMEOUT
            CONFIG_FAIL_MAKE_REQUEST
            CONFIG_FAIL_MMC_REQUEST
            CONFIG_FAIL_PAGE_ALLOC
            CONFIG_FAULT_INJECTION_DEBUG_FS
            ${CONFIGKEYSENABLE}"
        fi
        enable_feature=$((enable_feature>>1))

        for key in $CONFIGKEYSENABLE;
        do
            config_enable $key debian.master/config/config.common.ubuntu
        done

        for key in $CONFIGKEYSDISABLE;
        do
            config_disable $key debian.master/config/config.common.ubuntu
        done

        LANG=C fakeroot debian/rules defaultconfigs || true
        LANG=C fakeroot debian/rules -j`nproc` binary-headers binary-generic binary-perarch skipdbg=false

        cd ..
        dpkg -i linux*.deb
        touch ~/.stamp/COMPILE_UBUNTU
    fi
}

function archive_kernel() {
    if [ ! -f ~/.stamp/ARCHIVE_KERNEL ]; then
        cd ~/ubuntu-${code_name}/
        ddeb_pkg=`ls linux*.ddeb`
        dpkg -x ${ddeb_pkg} ./
        cp usr/lib/debug/boot/vmlinux* kernel/vmlinux

        cd kernel
        cp debian/build/build-generic/.config config
        git config --global user.email "xzou017@ucr.edu"
        git config --global user.name "etenal"
        git add -f vmlinux config
        git commit -m "add vmlinux and config"
        git archive --format=tar -o /tmp/ubuntu.tar.gz HEAD
        touch ~/.stamp/ARCHIVE_KERNEL
    fi
}

if [ $# -ne 3 ] && [ $# -ne 2 ] ; then
  echo "Usage ./deploy-ubuntu-image.sh [version_since version_until | commit] enable_feature"
  exit 1
fi

kernel_version=`uname -r`
kernel_major_version=`uname -r | cut -d- -f1`
kernel_minor_version=`uname -r | cut -d- -f2`
issue=`cat /etc/issue`
code_name=$(lsb_release -c | awk  '{print $2}')

if [ $# -eq 3 ]; then
    version_since=$1
    version_until=$2
    enable_feature=$3
    commit=''
fi

if [ $# -eq 2 ]; then
    commit=$1
    enable_feature=$2
    version_since=''
    version_until=''
fi

echo "deploying new image for ${issue} ${kernel_version}"
mkdir ~/.stamp || true

prepare_script

change_grub

install_necessary_packages

clone_ubuntu

compile_ubuntu

archive_kernel