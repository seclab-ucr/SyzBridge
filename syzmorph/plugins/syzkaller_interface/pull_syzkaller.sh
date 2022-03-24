#!/bin/bash
# Xiaochen Zou 2021, University of California-Riverside
#
# Usage ./pull_syzkaller.sh <syzkaller_repo_path> <syzkaller_branch>

set -ex

function set_git_config() {
  set +x
  echo "set user.email for git config"
  echo "Input email: "
  read email
  echo "set user.name for git config"
  echo "Input name: "
  read name
  git config --global user.email $email
  git config --global user.name $name
  set -x
}

echo "pull_syzkaller.sh"

if [ $# -ne 2 ]; then
  echo "Usage ./pull_syzkaller.sh <SYZ_REPO_PATH> <SYZ_COMMIT>"
  exit 1
fi

SYZ_REPO_PATH=$1
SYZ_COMMIT=$2
ARCH=$3
PROJECT_PATH=`pwd`
TOOLS_PATH=$PROJECT_PATH/tools

if [ ! -f "$TOOLS_PATH/.stamp/SETUP_GOLANG" ]; then
  echo "[+] Setup golang environment"
  cd $TOOLS_PATH
  wget https://dl.google.com/go/go1.14.2.linux-amd64.tar.gz
  tar -xf go1.14.2.linux-amd64.tar.gz
  mv go goroot
  rm go1.14.2.linux-amd64.tar.gz
  touch $TOOLS_PATH/.stamp/SETUP_GOLANG
fi

if [ ! -f "$TOOLS_PATH/.stamp/SETUP_SYZKALLER" ]; then
  echo "[+] Setup syzkaller"
  git clone https://github.com/google/syzkaller.git
  touch $TOOLS_PATH/.stamp/SETUP_SYZKALLER
fi

export GOPATH=$SYZ_REPO_PATH/gopath
export GOROOT=$PROJECT_PATH/tools/goroot
export PATH=$PATH:$GOROOT/bin

echo "[+] Building syzkaller"
if [ ! -d "$GOPATH/src/github.com/google/syzkaller" ]; then
    mkdir -p $GOPATH/src/github.com/google/ || echo "Dir exists"
    cd $GOPATH/src/github.com/google/
    cp -r $PROJECT_PATH/tools/gopath/src/github.com/google/syzkaller ./

    cd $GOPATH/src/github.com/google/syzkaller || exit 1
    make clean
    git stash --all || set_git_config
    if [ "$SYZ_COMMIT" != "" ]; then
        git checkout -f $SYZ_COMMIT || (git pull origin master > /dev/null 2>&1 && git checkout -f $SYZ_COMMIT)
    fi
fi

exit 0