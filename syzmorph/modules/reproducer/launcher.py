import os
import threading
import queue
import shutil

from infra.strings import *
from subprocess import Popen, STDOUT, PIPE, call
from infra.tool_box import chmodX, log_anything, regx_match
from modules.vm import VMInstance, VM
from modules.reproducer.error import CreateSnapshotError
from .build import Build

class Launcher(Build):
    def __init__(self, cfg, path_case, path_syzmorph, case_logger, path_linux=None, debug=False, qemu_num=3):
        Build.__init__(self, cfg, path_case, path_syzmorph, path_linux)
        self.case_logger = case_logger
        self.qemu_num = qemu_num
        self.debug = debug
        self.kill_qemu = False
        self.queue = queue.Queue()
        
    def save_crash_log(self, log, name):
        with open("{}/crash_log-{}".format(self.path_case, name), "w+") as f:
            for each in log:
                for line in each:
                    f.write(line+"\n")
                f.write("\n")
    
    def reproduce(self, *args):
        self.kill_qemu = False
        res = []
        trigger = False
        ever_success = False
        
        for i in range(0, self.qemu_num):
            x = threading.Thread(target=self._reproduce, args=(i, *args, ), name="trigger-{}".format(i))
            x.start()
            x.join()
            
            [crashes, high_risk, qemu_fail] = self.queue.get(block=True)
            if not ever_success:
                ever_success = qemu_fail
                if self.qemu_num < 5:
                    self.qemu_num += 1
            if not trigger and high_risk:
                trigger = high_risk
                res = crashes
                self.kill_qemu = True
                self.save_crash_log(res, self.type_name)
                if res == []:
                    res = crashes
                break
        if len(res) == 1 and isinstance(res[0], str):
            self.case_logger.error(res[0])
            return [], trigger
        return res, trigger
    
    def _reproduce(self, th_index, c_hash, work_dir, func, root, log_name=None, cpu="8", mem="8G"):
        qemu = self.launch_qemu(c_hash, work_dir, log_suffix=str(th_index), log_name=log_name, cpu=cpu, mem=mem)
        
        poc_path = os.path.join(work_dir, "poc")
        if not os.path.exists(poc_path):
            self.case_logger.error("POC path not found: {}".format(poc_path))
        self.start_reproducing(th_index, qemu, poc_path, func, root)
        return
    
    def launch_qemu(self, c_hash, work_path, log_suffix="", log_name=None, cpu="8", mem="8G"):
        if log_name is None:
            log_name = "qemu-{0}-{1}.log".format(c_hash, self.type_name)
        qemu = VM(linux=self.path_linux, vmtype=self.vmtype, hash_tag=c_hash, vmlinux=self.vmlinux, port=self.ssh_port, 
            image=self.image_path, work_path=work_path, cpu=cpu, mem=mem,
            log_name=log_name, log_suffix=log_suffix,
            key=self.ssh_key, timeout=10*60, debug=self.debug)
        qemu.logger.info("QEMU-{} launched.\n".format(log_suffix))
        return qemu
    
    def start_reproducing(self, th_index, qemu, poc_path, func, root):
        self.case_logger.info("Waiting qemu to launch")
        qemu.run(alternative_func=func, args=(th_index, poc_path, self.queue, root))

    def kill_proc_by_port(self, ssh_port):
        p = Popen("lsof -i :{} | awk '{{print $2}}'".format(ssh_port), shell=True, stdout=PIPE, stderr=PIPE)
        is_pid = False
        pid = -1
        with p.stdout as pipe:
            for line in iter(pipe.readline, b''):
                line = line.strip().decode('utf-8')
                if line == 'PID':
                    is_pid = True
                    continue
                if is_pid:
                    pid = int(line)
                    call("kill -9 {}".format(pid), shell=True)
                    break
        