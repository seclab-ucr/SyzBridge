#!/bin/bash
# Xiaochen Zou 2022, University of California-Riverside
#
# Usage ./check-poc-feature.sh FEATURE

set -ex
echo "running check-poc-feature.sh"

if [ $# -ne 1 ]; then
  echo "Usage ./check-poc-feature.sh FEATURE"
  exit 1
fi

FEATURE=$1

# FEATURE_LOOP_DEVICE
if [[ $((FEATURE&1)) == 1 ]]; then
    echo "FEATURE_LOOP_DEVICE"
    # check if loop device is created
    DEV_LIST=`losetup -a | awk '{{print $1}}'`
    echo "Busy loop devices:\n" $DEV_LIST

    echo $DEV_LIST |
    while read -r line; do \
        DEV_NAME=${line//:/ }; \
        echo "free loop device $DEV_NAME"; \
        umount $DEV_NAME > /dev/null 2>&1; \
    done
fi