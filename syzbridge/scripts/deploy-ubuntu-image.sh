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

function enable_extra_config() {
    if [ -f "/root/enable_extra_config" ]; then
        cat /root/disable_extra_config |
        while read -r key; 
        do
            config_enable $key debian.master/config/config.common.ubuntu
            config_enable $key debian.master/config/amd64/config.common.amd64
            config_enable $key debian.master/config/amd64/config.flavour.generic
        done < ~/enable_extra_config
    fi
}

function disable_extra_config() {
    if [ -f "/root/disable_extra_config" ]; then
        cat /root/disable_extra_config |
        while read -r key; 
        do
            config_disable $key debian.master/config/config.common.ubuntu
            config_disable $key debian.master/config/amd64/config.common.amd64
            config_disable $key debian.master/config/amd64/config.flavour.generic
        done < ~/disable_extra_config
    fi
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

    # Disable auto update
    rm /etc/apt/apt.conf.d/20auto-upgrades
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

        # Known issue 1: ubuntu-22.04 installs tiny-initramfs along with linux dep packages
        # This cause kernel from locating lvm disk
        apt-get update || sleep 30 && apt-get update
        #apt-get install -y asciidoc asciidoc-base asciidoc-common autoconf automake autopoint autotools-dev bison build-essential bzip2 ca-certificates-java cpp cpp-11 dctrl-tools debhelper debugedit default-jdk-headless default-jre-headless dh-autoreconf dh-strip-nondeterminism dkms docbook-dsssl docbook-utils docbook-xml docbook-xsl docutils-common dpkg-dev dvipng dwz fig2dev flex fontconfig fontconfig-config fonts-dejavu-core fonts-font-awesome fonts-lato fonts-lmodern fonts-noto-cjk fonts-urw-base35 g++ g++-11 gcc gcc-11 gcc-11-base gettext ghostscript graphviz hicolor-icon-theme imagemagick imagemagick-6-common imagemagick-6.q16 intltool-debian java-common latexmk libann0 libaom3 libapache-pom-java libarchive-zip-perl libasan6 libasound2 libasound2-data libatomic1 libaudit-dev libavahi-client3 libavahi-common-data libavahi-common3 libc-dev-bin libc6-dev libcairo-gobject2 libcairo2 libcap-dev libcap-ng-dev libcc1-0 libcdt5 libcgraph6 libcommons-logging-java libcommons-parent-java libcrypt-dev libcups2 libdatrie1 libdav1d5 libde265-0 libdebhelper-perl libdeflate0 libdpkg-perl libdw-dev libelf-dev libfftw3-double3 libfile-stripnondeterminism-perl libfontbox-java libfontconfig1 libgcc-11-dev libgd3 libgdk-pixbuf-2.0-0 libgdk-pixbuf2.0-common libgomp1 libgraphite2-3 libgs9 libgs9-common libgts-0.7-5 libgvc6 libgvpr2 libharfbuzz0b libheif1 libiberty-dev libice6 libidn12 libijs-0.35 libisl23 libitm1 libjbig0 libjbig2dec0 libjpeg-turbo8 libjpeg8 libjs-jquery libjs-sphinxdoc libjs-underscore libkpathsea6 liblab-gamut1 liblcms2-2 liblqr-1-0 liblsan0 libltdl7 liblzma-dev libmagickcore-6.q16-6 libmagickwand-6.q16-6 libmpc3 libnetpbm10 libnewt-dev libnsl-dev libnuma-dev libopenjp2-7 libosp5 libostyle1c2 libpango-1.0-0 libpangocairo-1.0-0 libpangoft2-1.0-0 libpaper-utils libpaper1 libpathplan4 libpcsclite1 libpdfbox-java libpixman-1-0 libpng-dev libptexenc1 libquadmath0 librsvg2-2 librsvg2-bin libsgmls-perl libslang2-dev libsm6 libssl-dev libstdc++-11-dev libsub-override-perl libsynctex2 libteckit0 libtexlua53 libtexluajit2 libthai-data libthai0 libtiff5 libtirpc-dev libtool libtsan0 libubsan1 libunwind-dev libwebp7 libwebpdemux2 libwebpmux3 libx265-199 libxaw7 libxcb-render0 libxcb-shm0 libxi6 libxml2-utils libxmu6 libxpm4 libxrender1 libxt6 libzzip-0-13 linux-libc-dev lto-disabled-list lynx lynx-common m4 make makedumpfile netpbm openjade openjdk-11-jdk-headless openjdk-11-jre-headless opensp pahole pkg-config po-debconf poppler-data preview-latex-style python3-alabaster python3-docutils python3-imagesize python3-packaging python3-pygments python3-roman python3-snowballstemmer python3-sphinx python3-sphinx-rtd-theme rpcsvc-proto sgml-base sgml-data sgmlspl sharutils sphinx-common sphinx-rtd-theme-common t1utils teckit tex-common texlive-base texlive-binaries texlive-fonts-recommended texlive-formats-extra texlive-latex-base texlive-latex-extra texlive-latex-recommended texlive-pictures texlive-plain-generic texlive-xetex tipa uuid-dev x11-common xdg-utils xml-core xmlto xsltproc zlib1g-dev libc6-dev-i386
        #apt-get build-dep -y linux-image-$(uname -r)
        apt-get install -y git trace-cmd psmisc fakeroot libncurses-dev gawk flex bison openssl libssl-dev dkms libelf-dev libudev-dev libpci-dev libiberty-dev autoconf gcc-multilib libc6-dev-i386 build-essential libc6-dev
        apt-get install -y libcap-dev python3-dev dwarves || true
        apt-get install -y linux-cloud-tools-common linux-tools-common || true
        apt-get build-dep -y linux linux-image-$(uname -r) || apt-get install -y debhelper kernel-wedge

        systemctl disable hv-kvp-daemon.service

        useradd -m syzbridge || true
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
            #tag=`git describe ${commit}`
            #echo "Switch to tag ${tag}"
            git checkout ${commit})
        else
            #tag=`git describe ${commit}`

            #echo "Switch to tag ${tag}"
            git checkout ${commit}
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
        # Disable nvidia driver cuz some of the url is withdrawn.
        sed -i '/do_dkms_nvidia/ s/true/false/' debian.master/rules.d/amd64.mk
        #printf '#!'"/usr/bin/perl\nexit 0" > debian/scripts/config-check
        #printf '#!'"/usr/bin/python3\nsys.exit(0)" > debian/scripts/module-check
        #chmod +x debian/scripts/config-check
        #chmod +x debian/scripts/module-check

        patch -p1 -f -i ~/dkms.patch || echo "probably fine"
        patch -p1 -f -i ~/mpi_oob_fix.patch || true

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
            config_enable $key debian.master/config/config.common.ubuntu
        done

        for key in $CONFIGKEYSDISABLE;
        do
            config_disable $key debian.master/config/config.common.ubuntu
        done

        enable_extra_config

        disable_extra_config

        sed -i "s/CONFIG_FRAME_WARN=1024/CONFIG_FRAME_WARN=0/g" debian.master/config/amd64/config.common.amd64

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
        ddeb_pkg=`ls linux-image*.ddeb`
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