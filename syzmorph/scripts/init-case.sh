#!/bin/bash
# Xiaochen Zou 2021, University of California-Riverside

set -ex

echo "running init-case.sh"

if [ $# -ne 3 ]; then
  echo "Usage ./init-case.sh CASE_PATH C_PROG SYZ_PROG"
  exit 1
fi

CASE_PATH=$1
C_PROG=$2
SYZ_PROG=$3

cd $CASE_PATH

if [ ! -d ".stamp" ]; then
    mkdir .stamp
fi

curl $C_PROG > poc.c || true
curl $SYZ_PROG > testcase || true

exit 0