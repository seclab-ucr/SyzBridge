#!/bin/bash
# Xiaochen Zou 2020, University of California-Riverside
#
# Usage ./run-script.sh command ssh_port image_path case_path

set -ex

echo "running run-script.sh"

if [ $# -ne 5 ]; then
    echo "Usage ./run-script.sh ssh_port case_path ssh_key user"
    exit 1
fi

PORT=$1
CASE_PATH=$2
KEY=$3
USER=$4
BASH_PATH=$5

cd $CASE_PATH
cat << EOF > run.sh
#!$BASH_PATH
while [ 1 ]
do
    rm -rf ./tmp || true
    mkdir ./tmp && cp ./poc ./tmp && cd ./tmp && chmod +x poc && ./poc
    cd ..
    sleep 1
done
EOF

if [ $PORT -eq -1 ]; then
    exit 0
fi
CMD="scp -F /dev/null -o UserKnownHostsFile=/dev/null \
    -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=no \
    -i $KEY -P $PORT ./run.sh $USER@localhost:~"
$CMD
exit 0