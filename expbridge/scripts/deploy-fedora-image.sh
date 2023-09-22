#!/bin/bash
# Xiaochen Zou 2022, University of California-Riverside
#
# Usage ./deploy-new-image.sh 

set -ex

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
        dnf install -y fedpkg fedora-packager rpmdevtools ncurses-devel pesign grubby psmisc trace-cmd glibc-devel.i686 glibc-devel

        useradd -m expbridge || true
        touch ~/.stamp/INSTALL_PACKAGES
    fi
}

function clone_fedora() {
    if [ ! -f ~/.stamp/CLONE_FEDORA ]; then
        mkdir fedora-${code_name} || (rm -rf fedora-${code_name} && mkdir fedora-${code_name})
        cd fedora-${code_name}
        git config --global http.postBuffer 524288000
        fedpkg clone -a kernel
        mv kernel ________________kernel
        cd ..
        touch ~/.stamp/CLONE_FEDORA
    fi
}

function compile_fedora() {
    if [ ! -f ~/.stamp/COMPILE_FEDORA ]; then
        cd ~/fedora-${code_name}/________________kernel
        
        if [ -z "${commit}" ]; then
            hash_val=''
            tag_name=''
            git log origin/f${code_name} --since="'${version_since}'" --until="'${version_until}'" -n 20 --pretty=oneline | \
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
        else
            git checkout ${commit}
        fi
        git checkout -B custom_kernel
        git branch -u origin/f${code_name}
        
        if [ $((enable_feature%2)) == 1 ]; then
            echo "CONFIG_KASAN=y" >> kernel-local
            echo "CONFIG_KASAN_INLINE=y" >> kernel-local
        fi
        enable_feature=$((enable_feature>>1))

        if [ $((enable_feature%2)) == 1 ]; then
            echo "CONFIG_UBSAN=y" >> kernel-local
            echo "CONFIG_UBSAN_BOUNDS=y" >> kernel-local
            echo "CONFIG_UBSAN_SHIFT=y" >> kernel-local
            echo "CONFIG_UBSAN_DIV_ZERO=y" >> kernel-local
            echo "CONFIG_UBSAN_BOOL=y" >> kernel-local
            echo "CONFIG_UBSAN_ENUM=y" >> kernel-local
            echo "CONFIG_UBSAN_ALIGNMENT=n" >> kernel-local
            echo "CONFIG_UBSAN_SANITIZE_ALL=y" >> kernel-local
            echo "CONFIG_TEST_UBSAN=n" >> kernel-local
        fi
        enable_feature=$((enable_feature>>1))

        if [ $((enable_feature%2)) == 1 ]; then
            echo "CONFIG_FAULT_INJECTION=y" >> kernel-local
            echo "CONFIG_FAILSLAB=y" >> kernel-local
            echo "CONFIG_FAIL_FUTEX=y" >> kernel-local
            echo "CONFIG_FAIL_IO_TIMEOUT=y" >> kernel-local
            echo "CONFIG_FAIL_MAKE_REQUEST=y" >> kernel-local
            echo "CONFIG_FAIL_MMC_REQUEST=y" >> kernel-local
            echo "CONFIG_FAIL_PAGE_ALLOC=y" >> kernel-local
            echo "CONFIG_FAULT_INJECTION_DEBUG_FS=y" >> kernel-local
        fi
        enable_feature=$((enable_feature>>1))
        if [ $((enable_feature%2)) == 1 ]; then
            echo "CONFIG_DEBUG_DEVRES=y" >> kernel-local
            echo "CONFIG_DEBUG_INFO=y" >> kernel-local
            echo "CONFIG_DEBUG_INFO_BTF=y" >> kernel-local
            echo "CONFIG_DEBUG_INFO_BTF_MODULES=y" >> kernel-local
            echo "CONFIG_DEBUG_FS=y" >> kernel-local
            echo "CONFIG_DEBUG_KERNEL=y" >> kernel-local
            echo "CONFIG_DEBUG_MISC=y" >> kernel-local
            echo "CONFIG_DEBUG_OBJECTS=y" >> kernel-local
            echo "CONFIG_DEBUG_OBJECTS_FREE=y" >> kernel-local
            echo "CONFIG_DEBUG_OBJECTS_TIMERS=y" >> kernel-local
            echo "CONFIG_DEBUG_OBJECTS_WORK=y" >> kernel-local
            echo "CONFIG_DEBUG_OBJECTS_RCU_HEAD=y" >> kernel-local
            echo "CONFIG_DEBUG_RT_MUTEXES=y" >> kernel-local
            echo "CONFIG_DEBUG_SPINLOCK=y" >> kernel-local
            echo "CONFIG_DEBUG_MUTEXES=y" >> kernel-local
            echo "CONFIG_DEBUG_LIST=y" >> kernel-local
            echo "CONFIG_DEBUG_PLIST=y" >> kernel-local
            echo "CONFIG_DEBUG_SG=y" >> kernel-local
            echo "CONFIG_DEBUG_NOTIFIERS=y" >> kernel-local
            echo "CONFIG_DEBUG_CREDENTIALS=y" >> kernel-local
        fi
        enable_feature=$((enable_feature>>1))
	    sed -i '/process_configs.sh $OPTS/d' kernel.spec
        patch -p1 -f -i ~/kernel_spec.patch || sed -i 's/%define listnewconfig_fail 1/%define listnewconfig_fail 0/' kernel.spec
	dnf -y builddep kernel.spec

        # https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/patch/?id=854e55ad289ef8888e7991f0ada85d5846f5afb9
        # f28 suffers from this bug, patch it in the fly.
        fedpkg local

        dnf install -y --nogpgcheck ./x86_64/kernel-*.rpm
        touch ~/.stamp/COMPILE_FEDORA
    fi
}

function archive_kernel() {
    cd ~/fedora-${code_name}/________________kernel/
    kernel_dir=`ls -d kernel*/`
    cd ${kernel_dir}
    linux_dir=`ls -d linux*/`
    cd ${linux_dir}
    if [ ! -f ~/.stamp/ARCHIVE_KERNEL ]; then
        mv .config config
        tar --exclude='*.o' -czf fedora.tar.gz ./*
        mv fedora.tar.gz /tmp
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

clone_fedora

compile_fedora

archive_kernel