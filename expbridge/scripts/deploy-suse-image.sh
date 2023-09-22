#!/bin/bash
# Xiaochen Zou 2023, University of California-Riverside
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
    systemctl disable dnf-makecache.service
    systemctl disable dnf-makecache.timer
    systemctl enable dhclient.service
}

function change_grub() {
    if [ ! -f ~/.stamp/CHANGE_GRUB ]; then
        sed -i 's/rhgb quiet/rhgb quiet nokaslr console=ttyS0 earlyprintk=serial loglevel=6/' /etc/default/grub
        grub2-mkconfig -o /boot/grub2/grub.cfg
        touch ~/.stamp/CHANGE_GRUB
    fi
}

function install_necessary_packages() {
    if [ ! -f ~/.stamp/INSTALL_PACKAGES ]; then
        zypper install rpm-build rpmdevtools git bc flex bison openssl-devel ncurses-devel zlib-devel
        zypper install trace-cmd psmisc fakeroot libncurses5 gawk flex bison openssl libopenssl-devel dkms pciutils-devel libudev-devel libpci3 autoconf glibc-devel-32bit glibc-32bit gcc-32bit
        useradd -m expbridge || true
        touch ~/.stamp/INSTALL_PACKAGES
    fi
}

function clone_suse() {
    if [ ! -f ~/.stamp/CLONE_FEDORA ]; then
        git config --global http.postBuffer 524288000
        git clone https://github.com/openSUSE/kernel-source.git
        git clone https://github.com/openSUSE/kernel
        touch ~/.stamp/CLONE_FEDORA
    fi
}

function patch_kernel() {
    cd ~/rpmbuild/SOURCES
    cp ~/22-x86-cpu_entry_area-move-it-out-of-the-fixmap.patch ~/rpmbuild/SOURCES/patches.arch
    rm ~/rpmbuild/SOURCES/patches.arch.tar.bz2
    tar -cvjSf patches.arch.tar.bz2 patches.arch
}
function compile_fedora() {
    if [ ! -f ~/.stamp/COMPILE_FEDORA ]; then
        cd kernel-source/
        
        if [ -z "${commit}" ]; then
            hash_val=''
            tag_name=''
            git log --since="'${version_since}'" --until="'${version_until}'" -n 20 --pretty=oneline | \
                ( while read -r line; do \
                    hash_val=`printf "${line}" | awk '{{print $1}}'`
                    tag_name=`printf "${line}" | awk '{{print $2}}'`
                    version=`printf "${line}" | awk '{{print $3}}'`
                    if [ -z "${version}" ]; then \
                        version=${tag_name}; \
                        if [[ ${version} =~ kernel-[0-9]+\.[0-9]+ ]]; then \
                            echo "MAGIC!!? ${version}"; \
                            commit=${hash_val}; \
                            break; \
                        fi \
                    else \
                        if [[ ${tag_name} == "Linux" ]]; then \
                            echo "MAGIC!!?${version}"; \
                            commit=${hash_val}; \
                            break; \
                        fi \
                    fi \
                done
            if [ -z "${commit}" ]; then
                echo "Cannot find a commit between ${version_since} and ${version_until}"
                exit 2
            fi
            git checkout ${commit})
            cd ../kernel
            git checkout ${commit}
        else
            git checkout ${commit}
            cd ../kernel
            git checkout ${commit}
        fi

        cd ../kernel-source/

        export LINUX_GIT=/root/kernel
        scripts/install-git-hooks
        scripts/sequence-patch.sh
        scripts/tar-up.sh

        cp config/x86_64/default ~/kernel/.config
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
            config_enable $key ~/kernel/.config
        done

        for key in $CONFIGKEYSDISABLE;
        do
            config_disable $key ~/kernel/.config
        done

        cd ~/kernel/
        sed -i "s/CONFIG_MODULE_SIG_KEY=\"certs\/signing_key.pem\"/CONFIG_MODULE_SIG_KEY=\"\"/g" .config
        make olddefconfig
        cp .config ~/kernel-source/config/x86_64/default

        rpmdev-setuptree
        cd ~
        mv kernel-source/* rpmbuild/SOURCES/
        cd rpmbuild/SOURCES
        mv kernel-source/* ./
        #mv 0004-x86-entry-build-thunk_-BITS-only-if-CONFIG_PREEMPTION-y.patch rpmbuild/SOURCES/patches.suse/
        
        rpmbuild -bb kernel-default.spec
        touch ~/.stamp/COMPILE_FEDORA
    fi
}

function archive_kernel() {
    cd ~/rpmbuild/BUILD/kernel-*/linux-*/
    cp ../config/x86_64/default .config
    if [ ! -f ~/.stamp/ARCHIVE_KERNEL ]; then
        mv .config config
        tar --exclude='*.o' -czf /tmp/suse.tar.gz ./*
        touch ~/.stamp/ARCHIVE_KERNEL
    fi
}

if [ $# -ne 4 ] && [ $# -ne 3 ] ; then
  echo "Usage ./deploy-fedora-image.sh [version_since version_until | commit] enable_feature code_name"
  exit 1
fi

kernel_version=`uname -r`
kernel_major_version=`uname -r | cut -d- -f1`
kernel_minor_version=`uname -r | cut -d- -f2`
issue=`cat /etc/issue`

if [ $# -eq 4 ]; then
    version_since=$1
    version_until=$2
    enable_feature=$3
    code_name=$4
    commit=''
fi

if [ $# -eq 3 ]; then
    commit=$1
    enable_feature=$2
    code_name=$3
    version_since=''
    version_until=''
fi

echo "deploying new image for ${issue} ${kernel_version}"
mkdir ~/.stamp || true

prepare_script

change_grub

install_necessary_packages

clone_suse

compile_suse

archive_kernel