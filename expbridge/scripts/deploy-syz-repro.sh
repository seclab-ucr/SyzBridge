#!/bin/bash
# Xiaochen Zou 2020, University of California-Riverside
#
# Usage ./deploy-syz-repro.sh command plugin_path

echo "running deploy-syz-repro.sh"

if [ $# -ne 2 ]; then
    echo "Usage ./deploy-syz-repro.sh command plugin_path"
    exit 1
fi

COMMAND=$1
PLUGIN_PATH=$2

RAW_COMMAND=`echo $COMMAND | sed -E "s/ -enable=[a-z_]+(,[a-z_]+)*//g"`
NON_REPEAT_COMMAND=`echo $COMMAND | sed -E "s/ -repeat=0/ -repeat=1/g; s/ -procs=[0-9]+/ -procs=1/g"`
NON_REPEAT_RAW_COMMAND=`echo $RAW_COMMAND | sed -E "s/ -repeat=0/ -repeat=1/g; s/ -procs=[0-9]+/ -procs=1/g"`

cd $PLUGIN_PATH/ || exit 1
cat << EOF > run_poc.sh
#!/bin/bash
set -ex

# cprog somehow work not as good as prog, an infinite loop even blocks the execution of syz-execprog
#if [ -f "./poc" ]; then
#    ./poc
#fi

RAW=\$1

for i in {1..10}
do
    # some crashes may be triggered after current process exit
    # some crashes need race-condition or multiple executions
    if [ "\$RAW" != "0" ]; then
        ${NON_REPEAT_RAW_COMMAND}
        ${RAW_COMMAND}
    else
        # old version syz-execprog may not support -enable
        ${NON_REPEAT_COMMAND} || ${NON_REPEAT_RAW_COMMAND}
        ${COMMAND} || ${RAW_COMMAND}
    fi
    
    #Sometimes the testcase is not required to repeat, but we still give a shot
    sleep 5
done
EOF
exit 0