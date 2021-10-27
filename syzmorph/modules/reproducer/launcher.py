import os
import threading
import queue
import time

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
    
    def prepare(self, syz_commit):
        self.kill_qemu = False
        res = []
        trigger = False
        ever_success = False
        
        for i in range(0, self.qemu_num):
            x = threading.Thread(target=self.launch, args=(i, syz_commit, ), name="trigger-{}".format(i))
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
    
    def launch(self, th_index, c_hash):
        if self.vmtype == VMInstance.UBUNTU:
            if self.create_snapshot():
                raise CreateSnapshotError
        log_name = "qemu-{0}-{1}.log".format(c_hash, self.type_name)
        qemu = VM(linux=self.path_linux, vmtype=self.vmtype, hash_tag=c_hash, vmlinux=self.vmlinux, port=self.ssh_port, 
            image=self.image_path, proj_path="{}/".format(self.path_case), cpu="8", mem="8G",
            log_name=log_name, log_suffix=str(th_index),
            key=self.ssh_key, timeout=10*60, debug=self.debug)
        qemu.logger.info("QEMU-{} launched.\n".format(th_index))
        
        poc_path = os.path.join(self.path_case, "poc")
        self.launch_qemu(th_index, qemu, poc_path)
        return
    
    def launch_qemu(self, th_index, qemu, poc_path):
        extract_report = False
        qemu_close = False
        out_begin = 0
        record_flag = 0
        kasan_flag = 0
        write_flag = 0
        double_free_flag = 0
        read_flag = 0
        crash = []
        res = []
        trgger_hunted_bug = False
        self.case_logger.info("Waiting qemu to launch")

        p = qemu.run()

        try:
            while not qemu_close:
                # We need one more iteration to get remain output from qemu
                if p.poll() != None and not qemu.qemu_ready:
                    qemu_close = True
                if qemu.qemu_ready and out_begin == 0:
                    self.run_poc(qemu, poc_path)
                    extract_report=True
                if extract_report:
                    out_end = len(qemu.output)
                    for line in qemu.output[out_begin:]:
                        if regx_match(call_trace_regx, line) or \
                        regx_match(message_drop_regx, line):
                            record_flag = 1
                        if regx_match(boundary_regx, line) or \
                        regx_match(panic_regx, line):
                            if record_flag == 1:
                                res.append(crash)
                                crash = []
                                if kasan_flag and (write_flag or read_flag or double_free_flag):
                                    trgger_hunted_bug = True
                                    if write_flag:
                                        self.logger.debug("QEMU threaded {}: OOB/UAF write triggered".format(th_index))
                                    if double_free_flag:
                                        self.logger.debug("QEMU threaded {}: Double free triggered".format(th_index))
                                    if read_flag:
                                        self.logger.debug("QEMU threaded {}: OOB/UAF read triggered".format(th_index)) 
                                    qemu.kill_qemu = True                      
                                    break
                            record_flag = 1
                            continue
                        if (regx_match(kasan_mem_regx, line) and 'null-ptr-deref' not in line):
                            kasan_flag = 1
                        if regx_match(write_regx, line):
                            write_flag = 1
                        if regx_match(kasan_double_free_regx, line):
                            double_free_flag = 1
                        if regx_match(read_regx, line):
                            read_flag = 1
                        if record_flag or kasan_flag:
                            crash.append(line)
                    out_begin = out_end
        except Exception as e:
            self.case_logger.error("Exception occur when reporducing crash: {}".format(e))
            if p.poll() == None:
                p.kill()
        if not extract_report:
            res = ['QEMU threaded {}: Error occur at booting qemu'.format(th_index)]
            self.kill_proc_by_port(self.ssh_port)
            if p.poll() == None:
                p.kill()
        self.queue.put([res, trgger_hunted_bug, qemu.qemu_fail])

    def run_poc(self, qemu, poc_path):
        qemu.upload(user="root", src=[poc_path], dst="/root", wait=True)
        self.case_logger.info("running PoC")
        script = "syzmorph/scripts/run-script.sh"
        chmodX(script)
        p = Popen([script, str(self.ssh_port), self.path_case, self.ssh_key],
            stderr=STDOUT,
            stdout=PIPE)
        with p.stdout:
            log_anything(p.stdout, self.case_logger, self.debug)
        # It looks like scp returned without waiting for all file finishing uploading.
        # Sleeping for 1 second to ensure everything is ready in vm
        time.sleep(1)
        qemu.command(cmds="chmod +x run.sh && ./run.sh", user="root", wait=False)
        return

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
        