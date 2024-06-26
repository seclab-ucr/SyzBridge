#!/bin/bash
# Xiaochen Zou 2020, University of California-Riverside
#
# Usage ./requirements.sh

set -ex
PROJECT_PATH=$(pwd)
TOOLS_PATH="$(pwd)/tools"
if [ ! -f "$(pwd)/tools/.stamp/ENV_SETUP" ]; then
  sudo apt-get update
  sudo apt-get -y install git qemu-system-x86 debootstrap flex bison libssl-dev libelf-dev cmake libxml2-dev xz-utils libmpfr-dev
  if [ ! -f "/usr/lib/x86_64-linux-gnu/libmpfr.so.4" ]; then
    sudo ln -s /usr/lib/x86_64-linux-gnu/libmpfr.so /usr/lib/x86_64-linux-gnu/libmpfr.so.4
  fi
  touch $TOOLS_PATH/.stamp/ENV_SETUP
fi

if [ ! -d "$TOOLS_PATH/.stamp" ]; then
  mkdir -p $TOOLS_PATH/.stamp
fi

cd $TOOLS_PATH

echo "[+] Download pwndbg"
if [ ! -f "$TOOLS_PATH/.stamp/SETUP_PWNDBG" ]; then
  git clone https://github.com/pwndbg/pwndbg.git pwndbg
  cd pwndbg
  git checkout f642efbd92e30c7b892b5e816d353cc5a03e5cb5
  ./setup.sh
  touch $TOOLS_PATH/.stamp/SETUP_PWNDBG
  cd ..
fi

echo "[+] Building image"
cd $TOOLS_PATH
if [ ! -f "$TOOLS_PATH/.stamp/BUILD_IMAGE" ]; then
  if [ ! -d "img" ]; then
    mkdir img
  fi
  cd img
  if [ ! -f "*.img" ]; then
    wget https://raw.githubusercontent.com/google/syzkaller/master/tools/create-image.sh
    chmod +x ./create-image.sh
    ./create-image.sh -s 10240 -d bullseye
    rm bullseye.img.key || true
    mv bullseye.id_rsa bullseye.img.key
    chmod 400 bullseye.img.key
    touch $TOOLS_PATH/.stamp/BUILD_IMAGE
  fi
  cd ..
fi

echo "[+] Building gcc and clang"
if [ ! -f "$TOOLS_PATH/.stamp/BUILD_GCC_CLANG" ]; then
  wget https://storage.googleapis.com/syzkaller/gcc-7.tar.gz > /dev/null
  tar xzf gcc-7.tar.gz
  mv gcc gcc-7
  rm gcc-7.tar.gz

  wget https://storage.googleapis.com/syzkaller/gcc-8.0.1-20180301.tar.gz > /dev/null
  tar xzf gcc-8.0.1-20180301.tar.gz
  mv gcc gcc-8.0.1-20180301
  rm gcc-8.0.1-20180301.tar.gz

  wget https://storage.googleapis.com/syzkaller/gcc-8.0.1-20180412.tar.gz > /dev/null
  tar xzf gcc-8.0.1-20180412.tar.gz
  mv gcc gcc-8.0.1-20180412
  rm gcc-8.0.1-20180412.tar.gz

  wget https://storage.googleapis.com/syzkaller/gcc-9.0.0-20181231.tar.gz > /dev/null
  tar xzf gcc-9.0.0-20181231.tar.gz
  mv gcc gcc-9.0.0-20181231
  rm gcc-9.0.0-20181231.tar.gz

  wget https://storage.googleapis.com/syzkaller/gcc-10.1.0-syz.tar.xz > /dev/null
  tar xf gcc-10.1.0-syz.tar.xz
  mv gcc-10 gcc-10.1.0-20200507
  rm gcc-10.1.0-syz.tar.xz

  wget https://storage.googleapis.com/syzkaller/clang-kmsan-329060.tar.gz > /dev/null
  tar xzf clang-kmsan-329060.tar.gz
  mv clang-kmsan-329060 clang-7-329060
  rm clang-kmsan-329060.tar.gz

  wget https://storage.googleapis.com/syzkaller/clang-kmsan-334104.tar.gz > /dev/null
  tar xzf clang-kmsan-334104.tar.gz
  mv clang-kmsan-334104 clang-7-334104
  rm clang-kmsan-334104.tar.gz

  wget https://storage.googleapis.com/syzkaller/clang-kmsan-343298.tar.gz > /dev/null
  tar xzf clang-kmsan-343298.tar.gz
  mv clang-kmsan-343298 clang-8-343298
  rm clang-kmsan-343298.tar.gz

  wget https://storage.googleapis.com/syzkaller/clang_install_c2443155.tar.gz > /dev/null
  tar xzf clang_install_c2443155.tar.gz
  mv clang_install_c2443155 clang-10-c2443155
  rm clang_install_c2443155.tar.gz

  wget https://storage.googleapis.com/syzkaller/clang-11-prerelease-ca2dcbd030e.tar.xz > /dev/null
  tar xf clang-11-prerelease-ca2dcbd030e.tar.xz
  mv clang clang-11-ca2dcbd030e
  rm clang-11-prerelease-ca2dcbd030e.tar.xz

  touch $TOOLS_PATH/.stamp/BUILD_GCC_CLANG
fi

echo "[+] Setup golang environment"
if [ ! -f "$TOOLS_PATH/.stamp/SETUP_GOLANG" ]; then
  wget https://go.dev/dl/go1.20.4.linux-amd64.tar.gz
  tar -xf go1.20.4.linux-amd64.tar.gz
  mv go goroot
  GOPATH=`pwd`/gopath
  if [ ! -d "gopath" ]; then
    mkdir gopath
  fi
  rm go1.20.4.linux-amd64.tar.gz
  touch $TOOLS_PATH/.stamp/SETUP_GOLANG
fi

echo "[+] Setup syzkaller"
if [ ! -f "$TOOLS_PATH/.stamp/SETUP_SYZKALLER" ]; then
  mkdir -p $GOPATH/src/github.com/google/ || echo "Dir exists"
  cd $GOPATH/src/github.com/google/
  rm -rf syzkaller || echo "syzkaller does not exist"
  git clone https://github.com/google/syzkaller.git
  touch $TOOLS_PATH/.stamp/SETUP_SYZKALLER
fi
