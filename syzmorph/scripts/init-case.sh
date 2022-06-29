#!/bin/bash
# Xiaochen Zou 2021, University of California-Riverside

set -ex

echo "running init-case.sh"

if [ $# -ne 2 ]; then
  echo "Usage ./init-case.sh CASE_PATH C_PROG"
  exit 1
fi

CASE_PATH=$1
C_PROG=$2

cd $CASE_PATH

if [ ! -d ".stamp" ]; then
    mkdir .stamp
fi

NO_C_REPRO=0
curl $C_PROG > poc.c || NO_C_REPRO=1

exit 0