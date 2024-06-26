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

function compile_with_patches() {
  grep -E "New address family defined, please update secclass_map" make.log || false
  patch -p1 -i $PROJECT_PATH/syzbridge/resources/PF_MAX.patch
  make -j$N_CORES CC=$COMPILER > make.log 2>&1
}

function copy_log_then_exit() {
  LOG=$1
  cp $LOG $CASE_PATH/$LOG-deploy_linux
  exit 1
}

function config_disable() {
  key=$1
  if [ "$key" != "" ]; then
    sed -i "s/$key=n/# $key is not set/g" .config
    sed -i "s/$key=m/# $key is not set/g" .config
    sed -i "s/$key=y/# $key is not set/g" .config
    grep $key .config || echo "# $key is not set" >> .config
  fi
}

function config_enable() {
  key=$1
  if [ "$key" != "" ]; then
    sed -i "s/$key=n/$key=y/g" .config
    sed -i "s/$key=m/$key=y/g" .config
    sed -i "s/# $key is not set/$key=y/g" .config
    grep $key .config || echo "$key=y" >> .config
  fi
}

function get_linux() {
  repo=$1
  version=$2
  wget $repo > /dev/null
  tar -xf linux-$version.tar.gz
  rm linux-$version.tar.gz
  cd linux-$version
}

function build_linux_folder {
  LINUX_FOLDER=$1
  LINUX0=$2
  KERNEL=$3
  if [ $LINUX0 == "LINUX0" ]; then
    if [ $KERNEL == "upstream" ]; then
      git clone https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/ $LINUX_FOLDER
    fi
    if [ $KERNEL == "stable" ]; then
      git clone https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git $LINUX_FOLDER
    fi
    if [ $KERNEL == "linux-next" ]; then
      git clone https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git $LINUX_FOLDER
    fi
    if [ $KERNEL == "net" ]; then
      git clone https://git.kernel.org/pub/scm/linux/kernel/git/netdev/net.git $LINUX_FOLDER
    fi
    if [ $KERNEL == "net-next" ]; then
      git clone https://git.kernel.org/pub/scm/linux/kernel/git/netdev/net-next.git $LINUX_FOLDER
    fi
    if [ $KERNEL == "bpf-next" ]; then
      git clone https://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf-next.git/ $LINUX_FOLDER
    fi
    if [ $KERNEL == "bpf" ]; then
      git clone https://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf.git/ $LINUX_FOLDER
    fi
    if [ $KERNEL == "kmsan" ]; then
      git clone https://github.com/google/kmsan.git $LINUX_FOLDER
    fi
  else
    cp -rp $LINUX0 $LINUX_FOLDER
  fi
}

if [ $# -lt 14 ]; then
  echo "Usage ./deploy-linux.sh gcc_version case_path max_compiling_kernel linux_commit config_url image linux_repo linux_version index kernel patch keep_config extra_cmd branch"
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
KERNEL=${10}
PATCH=${11}
KEEP_CONFIG=${12}
EXTRA_CMD=${13}
BRANCH=${14}

cd $CASE_PATH || exit 1
if [ ! -d "compiler" ]; then
  mkdir compiler
fi
cd compiler
if [ ! -L "$CASE_PATH/compiler/compiler" ]; then
  if [ $KERNEL == "kmsan" ]; then
    COMPILER=$PROJECT_PATH/tools/clang-11-ca2dcbd030e/bin/clang
  fi
  ln -s $COMPILER ./compiler
fi

cd $CASE_PATH || exit 1
echo "[+] Copy image"
if [ ! -d "$CASE_PATH/img" ]; then
  mkdir -p $CASE_PATH/img
fi
cd img
if [ ! -L "$CASE_PATH/img/bullseye.img" ]; then
  ln -s $PROJECT_PATH/tools/img/$IMAGE.img ./bullseye.img
fi
if [ ! -L "$CASE_PATH/img/bullseye.img.key" ]; then
  ln -s $PROJECT_PATH/tools/img/$IMAGE.img.key ./bullseye.img.key
fi
cd ..

echo "[+] Building kernel"
OLD_INDEX=`ls -l linux-$KERNEL | rev | cut -d'-' -f 1`
if [ "$OLD_INDEX" != "$INDEX" ] || [ ! -e ./linux-$KERNEL ]; then
  rm -rf "./linux-$KERNEL" || echo "No linux repo"
  if [[ $KERNEL =~ linux-[0-9]+\.[0-9]+\.y$ ]]; then
    KERNEL="stable"
  fi
  LINUX0=$PROJECT_PATH/tools/linux-$KERNEL-0
  ls $LINUX0 || LINUX0="LINUX0"
  ls $PROJECT_PATH/tools/linux-$KERNEL-$INDEX || build_linux_folder $PROJECT_PATH/tools/linux-$KERNEL-$INDEX $LINUX0 $KERNEL
  ln -s $PROJECT_PATH/tools/linux-$KERNEL-$INDEX ./linux-$KERNEL
  if [ -f "$CASE_PATH/.stamp/BUILD_KERNEL" ]; then
      rm $CASE_PATH/.stamp/BUILD_KERNEL
  fi
fi

if [ ! -f "$CASE_PATH/.stamp/BUILD_KERNEL" ]; then
    if [ -z $LINUX_REPO ]; then
      cd linux-$KERNEL
    else
      cd $LINUX_REPO
    fi

    if [ $COMMIT == "0" ]; then
      cd linux-$LINUX_VERSION || get_linux $LINUX_REPO $LINUX_VERSION
    else
      # If terminate syzbridge with ctrl+c, some git repo may still be protected
      rm .git/index.lock || true 
      git stash || echo "it's ok"
      make clean > /dev/null || echo "it's ok"
      git clean -fdx > /dev/null || echo "it's ok"
      if [ ! -z $BRANCH ]; then
        git checkout -f $BRANCH || (git reset --hard HEAD && git fetch --all --tags > /dev/null && git checkout remotes/origin/master && (git pull --tags origin master > /dev/null || git pull --tags origin main > /dev/null) && git reset --hard origin/master > /dev/null && git checkout -f $BRANCH)
      fi
      git checkout -f $COMMIT || (git reset --hard HEAD && git fetch --all --tags > /dev/null && (git pull --tags origin master > /dev/null || git pull --tags origin main > /dev/null) && git reset --hard origin/master > /dev/null && git checkout -f $COMMIT)
    fi
    curl $CONFIG > .config
    # Panic on data corruption may stop the fuzzing session
    CONFIGKEYSENABLE="
    CONFIG_DEBUG_INFO
    CONFIG_FRAME_POINTER
    CONFIG_UNWINDER_FRAME_POINTER
    CONFIG_KPROBES
    CONFIG_OPTPROBES
    CONFIG_KPROBES_ON_FTRACE
    CONFIG_KRETPROBES
    CONFIG_FUNCTION_TRACER
    CONFIG_FUNCTION_GRAPH_TRACER
    CONFIG_DYNAMIC_FTRACE
    CONFIG_DYNAMIC_FTRACE_WITH_REGS
    CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS
    CONFIG_FUNCTION_PROFILER
    CONFIG_STACK_TRACER
    CONFIG_TRACER_MAX_TRACE
    CONFIG_SCHED_TRACER
    CONFIG_FTRACE_SYSCALLS
    CONFIG_TRACER_SNAPSHOT
    CONFIG_KPROBE_EVENTS
    CONFIG_BPF_KPROBE_OVERRIDE
    CONFIG_FTRACE_MCOUNT_RECORD
    CONFIG_TRACING_MAP
    CONFIG_HIST_TRIGGERS
    CONFIG_FUNCTION_ERROR_INJECTION
    CONFIG_CONSOLE_POLL
    CONFIG_GDB_SCRIPTS
    CONFIG_MAGIC_SYSRQ
    CONFIG_MAGIC_SYSRQ_SERIAL
    CONFIG_KGDB
    CONFIG_KGDB_SERIAL_CONSOLE
    CONFIG_SCHED_DEBUG
    CONFIG_RING_BUFFER_ALLOW_SWAP
    CONFIG_TRACE_PREEMPT_TOGGLE
    CONFIG_PREEMPT_TRACER
    CONFIG_HWLAT_TRACER
    CONFIG_EARLY_PRINTK_USB_XDBC
    "

    CONFIGKEYSDISABLE="
    CONFIG_HAVE_ARCH_KASAN
    CONFIG_KASAN
    CONFIG_KASAN_OUTLINE
    CONFIG_SLUB_DEBUG
    CONFIG_KCOV
    CONFIG_BUG_ON_DATA_CORRUPTION
    CONFIG_KASAN_INLINE
    CONFIG_RANDOMIZE_BASE
    CONFIG_PANIC_ON_OOPS
    CONFIG_X86_SMAP
    CONFIG_BOOTPARAM_SOFTLOCKUP_PANIC
    CONFIG_BOOTPARAM_HARDLOCKUP_PANIC
    CONFIG_BOOTPARAM_HUNG_TASK_PANIC
    CONFIG_F2FS_IO_TRACE
    CONFIG_AFS_FS
    CONFIG_KPROBE_EVENTS_ON_NOTRACE
    CONFIG_SYNTH_EVENT_GEN_TEST
    CONFIG_KPROBE_EVENT_GEN_TEST
    CONFIG_FAIL_FUNCTION
    CONFIG_LIVEPATCH
    CONFIG_SERIAL_KGDB_NMI
    CONFIG_ENABLE_MUST_CHECK
    CONFIG_KGDB_TESTS
    CONFIG_KGDB_LOW_LEVEL_TRAP
    CONFIG_KGDB_KDB
    CONFIG_DEBUG_OBJECTS
    CONFIG_DEBUG_STACK_USAGE
    CONFIG_DEBUG_VM
    CONFIG_DEBUG_VIRTUAL
    CONFIG_DEBUG_MEMORY_INIT
    CONFIG_DEBUG_PER_CPU_MAPS
    CONFIG_WQ_WATCHDOG
    CONFIG_DEBUG_PREEMPT
    CONFIG_PROVE_LOCKING
    CONFIG_DEBUG_RT_MUTEXES
    CONFIG_DEBUG_SPINLOCK
    CONFIG_DEBUG_MUTEXES
    CONFIG_DEBUG_WW_MUTEX_SLOWPATH
    CONFIG_DEBUG_RWSEMS
    CONFIG_DEBUG_LOCK_ALLOC
    CONFIG_DEBUG_ATOMIC_SLEEP
    CONFIG_DEBUG_LIST
    CONFIG_DEBUG_PLIST
    CONFIG_DEBUG_SG
    CONFIG_DEBUG_NOTIFIERS
    CONFIG_DEBUG_CREDENTIALS
    CONFIG_DEBUG_BOOT_PARAMS
    "

    if [ $KEEP_CONFIG == "0" ]; then
      for key in $CONFIGKEYSDISABLE;
      do
        config_disable $key
      done

      for key in $CONFIGKEYSENABLE;
      do
        config_enable $key
      done
    fi

    if [ -f "$CASE_PATH/enable_config" ]; then
      cat $CASE_PATH/enable_config |
      while read -r line; do \
          config_enable $line; \
      done
    fi

    if [ -f "$CASE_PATH/disable_config" ]; then
      cat $CASE_PATH/disable_config |
      while read -r line; do \
          config_disable $line; \
      done
    fi

    PATCH_TCP_CONG=0
    make olddefconfig CC=$COMPILER
    echo $PATCH 
    if [ ! -z "$PATCH" ]; then
      patch -p1 -i $PATCH || exit 2
    fi
    if [ ! -z "$EXTRA_CMD" ]; then
      eval $EXTRA_CMD || exit 2
    fi
    make -j$N_CORES CC=$COMPILER > make.log 2>&1 || cat make.log && PATCH_TCP_CONG=1
    if [ $PATCH_TCP_CONG == 1 ]; then
      echo "[+] Patching TCP congestion control"

      CONFIGKEYSDISABLE="
      CONFIG_TCP_CONG_CUBIC
      CONFIG_TCP_CONG_DCTCP
      CONFIG_TCP_CONG_BBR
      "
      for key in $CONFIGKEYSDISABLE;
      do
      config_disable $key
      done

      make olddefconfig CC=$COMPILER
      make -j$N_CORES CC=$COMPILER > make.log 2>&1 || compile_with_patches || copy_log_then_exit make.log
    fi
    rm $CASE_PATH/config || echo "It's ok"
    cp .config $CASE_PATH/config
    touch $CASE_PATH/.stamp/BUILD_KERNEL
fi

exit 0
