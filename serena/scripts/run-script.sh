#!/bin/bash
# Xiaochen Zou 2020, University of California-Riverside
#
# Usage ./run-script.sh command ssh_port image_path case_path

echo "running run-script.sh"

if [ $# -ne 2 ]; then
    echo "Usage ./run-script.sh ssh_port case_path"
    exit 1
fi

PORT=$1
CASE_PATH=$2

cd $CASE_PATH
cat << EOF > run.sh
#!/bin/bash
set -ex

if [ -f "./poc" ]; then
    for i in {1..1000}
    do
        ./poc
    done
fi

echo "Done running 1000 times poc" > done
EOF

CMD="scp -F /dev/null -o UserKnownHostsFile=/dev/null \
    -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=no \
    -i $CASE_PATH/id_rsa -P $PORT ./run.sh root@localhost:/root"
$CMD
exit 0