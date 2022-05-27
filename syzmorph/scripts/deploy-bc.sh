#!/bin/bash
# Xiaochen Zou 2020, University of California-Riverside
#
# Usage ./deplay-bc.sh linux_clone_path index case_path commit config

set -ex

echo "running deploy-bc.sh"

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

if [ $# -ne 3 ]; then
  echo "Usage ./deploy-bc.sh linux_path config llvm_build_path"
  exit 1
fi

LINUX_PATH=$1
CONFIG=$2
LLVM_PATH=$3
CLANG=${LLVM_PATH}/bin/clang

cd $LINUX_PATH

rm .config
cp $CONFIG .config


CONFIGKEYSDISABLE="
CONFIG_KASAN
CONFIG_KCOV
CONFIG_BUG_ON_DATA_CORRUPTION
CONFIG_DRM_I915
CONFIG_XEN
"

for key in $CONFIGKEYSDISABLE;
do
    config_disable $key
done

sed -i "s/CONFIG_MODULE_SIG_KEY=\"certs\/signing_key.pem\"/CONFIG_MODULE_SIG_KEY=\"\"/g" .config
sed -i "s/CONFIG_SYSTEM_TRUSTED_KEYS=\"debian\/canonical-certs.pem\"/CONFIG_SYSTEM_TRUSTED_KEYS=\"\"/g" .config
sed -i "s/CONFIG_SYSTEM_REVOCATION_KEYS=\"debian\/canonical-revoked-certs.pem\"/CONFIG_SYSTEM_REVOCATION_KEYS=\"\"/g" .config

make olddefconfig CC=$CLANG
make prepare CC=$CLANG
make -j`nproc` CC=$CLANG > make.log 2>&1 || echo "It's OK"

# save the dry run log
find -type f -name '*.o' -delete
make -n CC=$CLANG > clang_log || echo "It's OK"

exit 0