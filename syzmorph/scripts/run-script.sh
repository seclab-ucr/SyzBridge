#!/bin/bash
# Xiaochen Zou 2020, University of California-Riverside
#
# Usage ./run-script.sh command ssh_port image_path case_path

set -ex

echo "running run-script.sh"

if [ $# -ne 3 ]; then
    echo "Usage ./run-script.sh ssh_port case_path ssh_key"
    exit 1
fi

PORT=$1
CASE_PATH=$2
KEY=$3

cd $CASE_PATH
cat << EOF > run.sh
#!/bin/bash
set -ex

while [ 1 ]
do
    ./poc
done
EOF

CMD="scp -F /dev/null -o UserKnownHostsFile=/dev/null \
    -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=no \
    -i $KEY -P $PORT ./run.sh root@localhost:/root"
$CMD
exit 0