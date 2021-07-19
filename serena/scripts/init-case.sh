#!/bin/bash
# Xiaochen Zou 2021, University of California-Riverside

set -ex

echo "running init-case.sh"

if [ $# -ne 5 ]; then
  echo "Usage ./init-case.sh CASE_PATH IMAGE_PATH VMLINUX_PATH KEY_PATH C_PROG"
  exit 1
fi

CASE_PATH=$1
IMAGE_PATH=$2
VMLINUX_PATH=$3
KEY_PATH=$4
C_PROG=$5

cd $CASE_PATH

if [ ! -d ".stamp" ]; then
    mkdir .stamp
fi

NO_C_REPRO=0
curl $C_PROG > poc.c || NO_C_REPRO=1
if [ $NO_C_REPRO != 1 ]; then
  gcc -pthread -o poc poc.c
fi

rm $CASE_PATH/vmlinux || echo "pass"
rm $CASE_PATH/id_rsa || echo "pass"

ln -s $VMLINUX_PATH $CASE_PATH/vmlinux
ln -s $KEY_PATH $CASE_PATH/id_rsa

exit 0