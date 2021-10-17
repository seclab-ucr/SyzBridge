#!/bin/bash
# Xiaochen Zou 2020, University of California-Riverside
#
# Usage ./requirements.sh

if [ ! -f "$(pwd)/tools/.stamp/ENV_SETUP" ]; then
  sudo apt-get update
  sudo apt-get -y install git qemu-system-x86 debootstrap flex bison libssl-dev libelf-dev cmake libxml2-dev
fi

TOOLS_PATH="$(pwd)/tools"
if [ ! -d "$TOOLS_PATH/.stamp" ]; then
  mkdir -p $TOOLS_PATH/.stamp
fi

echo "[+] Download pwndbg"
if [ ! -f "$TOOLS_PATH/.stamp/SETUP_PWNDBG" ]; then
  git clone https://github.com/plummm/pwndbg_linux_kernel.git pwndbg
  cd pwndbg
  ./setup.sh
  touch $TOOLS_PATH/.stamp/SETUP_PWNDBG
  cd ..
fi

touch $TOOLS_PATH/.stamp/ENV_SETUP

#BUG: If multiple instances are running, may clean up others' flag
echo "[+] Clean unfinished jobs"
rm linux-*/.git/index.lock || echo "Removing index.lock"
echo "All set"
