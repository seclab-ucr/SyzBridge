#!/bin/bash
# Xiaochen Zou 2021, University of California-Riverside
#
# Usage ./deploy_linux gcc_version case_path max_compiling_kernel linux_commit config_url image

set -ex

echo "running deploy-linux.sh"

function clean_and_jump() {
  git stash --all
  git checkout -f $COMMIT
}

function copy_log_then_exit() {
  LOG=$1
  cp $LOG $CASE_PATH/$LOG-deploy_linux
  exit 1
}

function config_disable() {
  key=$1
  sed -i "s/$key=n/# $key is not set/g" .config
  sed -i "s/$key=m/# $key is not set/g" .config
  sed -i "s/$key=y/# $key is not set/g" .config
}

function config_enable() {
  key=$1
  sed -i "s/$key=n/# $key is not set/g" .config
  sed -i "s/$key=m/# $key is not set/g" .config
  sed -i "s/# $key is not set/$key=y/g" .config
}

function get_linux() {
  repo=$1
  version=$2
  wget $repo > /dev/null
  tar -xf linux-$version.tar.gz
  rm linux-$version.tar.gz
  cd linux-$version
}

if [ $# -ne 9 ]; then
  echo "Usage ./deploy_linux gcc_version case_path max_compiling_kernel linux_commit config_url image linux_repo linux_version index"
  exit 1
fi

COMPILER_VERSION=$1
CASE_PATH=$2
MAX_COMPILING_KERNEL=$3
PROJECT_PATH="$(pwd)"
N_CORES=$((`nproc` / $MAX_COMPILING_KERNEL))
echo "Compiler: "$COMPILER_VERSION | grep gcc && \
COMPILER=$PROJECT_PATH/tools/$COMPILER_VERSION/bin/gcc || COMPILER=$PROJECT_PATH/tools/$COMPILER_VERSION/bin/clang
COMMIT=$4
CONFIG=$5
IMAGE=$6
LINUX_REPO=$7
LINUX_VERSION=$8
INDEX=$9

cd $CASE_PATH || exit 1
if [ ! -d "compiler" ]; then
  mkdir compiler
fi
cd compiler
if [ ! -L "$CASE_PATH/compiler/compiler" ]; then
  ln -s $COMPILER ./compiler
fi

cd $CASE_PATH || exit 1
echo "[+] Copy image"
if [ ! -d "$CASE_PATH/img" ]; then
  mkdir -p $CASE_PATH/img
fi
cd img
if [ ! -L "$CASE_PATH/img/stretch.img" ]; then
  ln -s $PROJECT_PATH/tools/img/$IMAGE.img ./stretch.img
fi
if [ ! -L "$CASE_PATH/img/stretch.img.key" ]; then
  ln -s $PROJECT_PATH/tools/img/$IMAGE.img.key ./stretch.img.key
fi
cd ..

echo "[+] Building kernel"
OLD_INDEX=`ls -l linux | cut -d'-' -f 3`
if [ "$OLD_INDEX" != "$INDEX" ]; then
  rm -rf "./linux" || echo "No linux repo"
  ls $PROJECT_PATH/tools/linux-$INDEX || mkdir $PROJECT_PATH/tools/linux-$INDEX
  ln -s $PROJECT_PATH/tools/linux-$INDEX ./linux
  if [ -f "$CASE_PATH/.stamp/BUILD_KERNEL" ]; then
      rm $CASE_PATH/.stamp/BUILD_KERNEL
  fi
fi

if [ ! -f "$CASE_PATH/.stamp/BUILD_KERNEL" ]; then
    cd linux
    if [ -f "THIS_KERNEL_IS_BEING_USED" ]; then
        echo "This kernel is using by other thread"
        exit 1
    fi
    cd linux-$LINUX_VERSION || get_linux $LINUX_REPO $LINUX_VERSION
    curl $CONFIG > .config
    # Panic on data corruption may stop the fuzzing session
    CONFIGKEYSENABLE="
    CONFIG_HAVE_ARCH_KASAN
    CONFIG_KASAN
    CONFIG_KASAN_OUTLINE
    CONFIG_DEBUG_INFO
    CONFIG_FRAME_POINTER
    CONFIG_UNWINDER_FRAME_POINTER"

    CONFIGKEYSDISABLE="
    CONFIG_BUG_ON_DATA_CORRUPTION
    CONFIG_KASAN_INLINE
    CONFIG_RANDOMIZE_BASE
    CONFIG_PANIC_ON_OOPS
    CONFIG_X86_SMAP
    CONFIG_BOOTPARAM_SOFTLOCKUP_PANIC
    CONFIG_BOOTPARAM_HARDLOCKUP_PANIC
    CONFIG_BOOTPARAM_HUNG_TASK_PANIC
    "

    for key in $CONFIGKEYSDISABLE;
    do
    config_disable $key
    done

    for key in $CONFIGKEYSENABLE;
    do
    config_enable $key
    done


    make olddefconfig CC=$COMPILER
    make -j$N_CORES CC=$COMPILER > make.log 2>&1 || copy_log_then_exit make.log
    rm $CASE_PATH/config || echo "It's ok"
    cp .config $CASE_PATH/config
    touch THIS_KERNEL_IS_BEING_USED
    touch $CASE_PATH/.stamp/BUILD_KERNEL
fi

exit 0
