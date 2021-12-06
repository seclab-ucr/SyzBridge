#!/bin/bash
# Xiaochen Zou 2020, University of California-Riverside
#
# Usage ./run-script.sh command ssh_port image_path case_path

set -ex

echo "running run-script.sh"

if [ $# -ne 4 ]; then
    echo "Usage ./run-script.sh ssh_port case_path ssh_key user"
    exit 1
fi

PORT=$1
CASE_PATH=$2
KEY=$3
USER=$4

cd $CASE_PATH
cat << EOF > run.sh
#!/bin/bash
set -ex

echo "6" > /proc/sys/kernel/printk || true
chmod +x ./poc
set +ex
while [ 1 ]
do
    ./poc
done
EOF

CMD="scp -F /dev/null -o UserKnownHostsFile=/dev/null \
    -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=no \
    -i $KEY -P $PORT ./run.sh $USER@localhost:~"
$CMD
exit 0