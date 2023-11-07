#!/bin/bash
# Xiaochen Zou 2020, University of California-Riverside
#
# Usage ./deploy-syzkaller.sh case_path syz_repro_url ssh_port image_path syz_commit type c_repro i386
# EXITCODE: 2: syz-execprog supports -enable. 3: syz-execprog do not supports -enable.

set -ex
echo "running deploy-syzkaller.sh"

if [ $# -ne 5 ]; then
  echo "Usage ./deploy-syzkaller.sh plugin_path syz_repro_url syz_commit type i386"
  exit 1
fi

PLUGIN_PATH=$1
TESTCASE=$2
SYZKALLER=$3
TYPE=$4
I386=$5
EXITCODE=3
PROJECT_PATH=`pwd`
BIN_PATH=$PLUGIN_PATH/gopath/src/github.com/google/syzkaller
export GOROOT=`pwd`/tools/goroot
export PATH=$GOROOT/bin:$PATH

M32=""
ARCH="amd64"
if [ "$I386" != "None" ]; then
    M32="-m32"
    ARCH="386"
fi

cd $PLUGIN_PATH
if [ "$TYPE" == "1" ]; then
    cp $TESTCASE ./testcase || exit 1
else
    curl $TESTCASE > testcase
fi

if [ ! -d "$PLUGIN_PATH/gopath" ]; then
    mkdir -p $PLUGIN_PATH/gopath
fi
export GOPATH=$PLUGIN_PATH/gopath
mkdir -p $GOPATH/src/github.com/google/ || echo "Dir exists"
BIN_PATH=$PLUGIN_PATH
cd $GOPATH/src/github.com/google/
if [ ! -d "$GOPATH/src/github.com/google/syzkaller" ]; then
    cp -r $PROJECT_PATH/tools/gopath/src/github.com/google/syzkaller ./
    cd $GOPATH/src/github.com/google/syzkaller || exit 1

    git checkout -f $SYZKALLER || (git pull origin master > /dev/null 2>&1 && git checkout -f $SYZKALLER)
    make TARGETARCH=$ARCH TARGETVMARCH=amd64 execprog executor
    if [ -d "bin/linux_$ARCH" ]; then
        cp bin/linux_amd64/syz-execprog $BIN_PATH
        cp bin/linux_$ARCH/syz-executor $BIN_PATH
    else
        cp bin/syz-execprog $BIN_PATH
        cp bin/syz-executor $BIN_PATH
    fi
fi

if [ ! -f "$BIN_PATH/syz-execprog" ]; then
    SYZ_PATH=$CASE_PATH/poc/gopath/src/github.com/google/syzkaller/
    if [ -d "$SYZ_PATH/bin/linux_$ARCH" ]; then
        cp $SYZ_PATH/bin/linux_amd64/syz-execprog $BIN_PATH
        cp $SYZ_PATH/bin/linux_$ARCH/syz-executor $BIN_PATH
    else
        cp $SYZ_PATH/bin/syz-execprog $BIN_PATH
        cp $SYZ_PATH/bin/syz-executor $BIN_PATH
    fi
fi
exit $EXITCODE
