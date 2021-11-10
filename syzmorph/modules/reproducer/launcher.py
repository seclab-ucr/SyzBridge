import os
import threading
import queue
import shutil

from infra.strings import *
from subprocess import Popen, STDOUT, PIPE, call
from infra.tool_box import chmodX, log_anything, regx_match
from modules.vm import VMInstance, VM
from modules.reproducer.error import CreateSnapshotError

class Launcher:
    def __init__(self, path_case, path_syzmorph, ssh_port, case_logger, path_linux=None, debug=False, qemu_num=3):
        self.case_logger = case_logger
        self.path_case = path_case
        self.path_syzmorph = path_syzmorph
        self.image_path = None
        self.vmlinux = None
        self.ssh_key = None
        self.path_linux = path_linux
        self.qemu_num = qemu_num
        self.ssh_port = ssh_port
        self.type_name = ""
        self.debug = debug
        self.kill_qemu = False
        self.queue = queue.Queue()
    
    def setup(self, vmtype):
        self.vmtype = vmtype
        if vmtype == VMInstance.LTS:
            self.image_path = "{}/img/stretch.img".format(self.path_case)
            self.vmlinux = "{}/vmlinux".format(self.path_case)
            self.ssh_key = "{}/img/stretch.img.key".format(self.path_case)
            self.type_name = "lts"
        if vmtype == VMInstance.UBUNTU:
            self.image_path = "{}/ubuntu-20.04-snapshot.img".format(self.path_case)
            self.vmlinux = "{}/vmlinux".format(self.path_case)
            self.ssh_key = "{}/id_rsa".format(self.path_case)
            self.type_name = "ubuntu"
        if vmtype == VMInstance.UPSTREAM:
            self.image_path = "{}/img/stretch.img".format(self.path_case)
            self.vmlinux = "{}/vmlinux".format(self.path_case)
            self.ssh_key = "{}/img/stretch.img.key".format(self.path_case)
            self.type_name = "upstream"
    
    def reproduce(self, syz_commit, work_dir, func):
        self.kill_qemu = False
        res = []
        trigger = False
        ever_success = False
        
        for i in range(0, self.qemu_num):
            x = threading.Thread(target=self._reproduce, args=(i, syz_commit, work_dir, func, ), name="trigger-{}".format(i))
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
            self.logger.error(res[0])
            return [], trigger
        return res, trigger
        
    def save_crash_log(self, log, name):
        with open("{}/crash_log-{}".format(self.path_case, name), "w+") as f:
            for each in log:
                for line in each:
                    f.write(line+"\n")
                f.write("\n")
    
    def _reproduce(self, th_index, c_hash, work_dir, func, log_name=None, cpu="8", mem="8G"):
        qemu = self.launch_qemu(c_hash, work_dir, log_suffix=str(th_index), log_name=log_name, cpu=cpu, mem=mem)
        
        poc_path = os.path.join(work_dir, "poc")
        if os.path.exists(poc_path):
            os.remove(poc_path)
        shutil.copyfile(os.path.join(self.path_case, "poc"), poc_path)
        self.start_reproducing(th_index, qemu, poc_path, func)
        return
    
    def launch_qemu(self, c_hash, work_path, log_suffix="", log_name=None, cpu="8", mem="8G"):
        if self.vmtype == VMInstance.UBUNTU:
            if self.create_snapshot():
                raise CreateSnapshotError
        if log_name is None:
            log_name = "qemu-{0}-{1}.log".format(c_hash, self.type_name)
        qemu = VM(linux=self.path_linux, vmtype=self.vmtype, hash_tag=c_hash, vmlinux=self.vmlinux, port=self.ssh_port, 
            image=self.image_path, work_path=work_path, cpu=cpu, mem=mem,
            log_name=log_name, log_suffix=log_suffix,
            key=self.ssh_key, timeout=10*60, debug=self.debug)
        qemu.logger.info("QEMU-{} launched.\n".format(log_suffix))
        return qemu
    
    def start_reproducing(self, th_index, qemu, poc_path, func):
        self.case_logger.info("Waiting qemu to launch")
        qemu.run(alternative_func=func, args=(th_index, poc_path, self.queue,))

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
    
    def create_snapshot(self):
        dst = "{}/ubuntu-20.04-snapshot.img".format(self.path_case)
        src = "{}/tools/images/ubuntu-20.04.img".format(self.path_syzmorph)
        if os.path.isfile(dst):
            os.remove(dst)
        cmd = ["qemu-img", "create", "-f", "qcow2", "-b", src, dst]
        p = Popen(cmd, stderr=STDOUT, stdout=PIPE)
        with p.stdout:
            log_anything(p.stdout, self.case_logger, self.debug)
        exitcode = p.wait()
        return exitcode
        