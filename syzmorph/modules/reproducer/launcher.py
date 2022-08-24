import os
import queue
import multiprocessing
from re import T
import threading
from time import sleep

from infra.strings import *
from subprocess import Popen, PIPE, call
from modules.vm import VM
from .build import Build

class Launcher(Build):
    def __init__(self, cfg, manager):
        Build.__init__(self, cfg, manager)
        self.manager = manager
        self.case_logger = manager.case_logger
        self.debug = manager.debug
        self.kill_qemu = False
        self.queue = multiprocessing.Queue()
        
    def save_crash_log(self, log, name):
        with open("{}/crash_log-{}".format(self.path_case, name), "w+") as f:
            for each in log:
                for line in each:
                    f.write(line+"\n")
                f.write("\n")
    
    def need_repro(self):
        case = self.manager.case
        if case['affect'] != None:
            if self.distro_name in case['affect']:
                return True 
        else:
            if case['patch']['fixes'] == []:
                return True
            for fix in case['patch']['fixes']:
                if self.distro_name in fix['exclude']:
                    return False
            return True
    
    def reproduce(self, func, func_args, root, work_dir, vm_tag, attempt=3, **kwargs):
        self.kill_qemu = False
        res = []
        trigger = False
        ever_success = False
        remain = []
        
        i = 0
        while i < attempt:
            args = {'th_index':i, 'func':func, 'args':func_args, 'root':root, 'work_dir':work_dir, 'vm_tag':vm_tag + '-' + str(i), **kwargs}
            x = multiprocessing.Process(target=self._reproduce, kwargs=args, name="trigger-{}".format(i))
            x.start()
            self.log("Start reproducing {}, args {}".format(vm_tag + str(i), args))
            
            t = self.queue.get(block=True)
            if len(t) >= 3:
                crashes = t[0]
                high_risk = t[1] 
                qemu_fail = t[2]
                if len(t) > 3:
                    remain = t[3:]
                self.log("Reproducing done, crashes: {}, high_risk {}, qemu_fail {}".format(crashes, high_risk, qemu_fail))
                if qemu_fail:
                    continue
            else:
                self.log("Reproducing failed, ret {}".format(t))
                continue
            i += 1
            if not trigger and crashes != []:
                trigger = True
                res = crashes
                self.kill_qemu = True
                self.save_crash_log(res, self.distro_name)
                if res == []:
                    res = crashes
                break
        if len(res) == 1 and isinstance(res[0], str):
            self.case_logger.error(res[0])
            return [], trigger, remain
        return res, trigger, remain
    
    def _reproduce(self, th_index, func, args, root, work_dir, vm_tag, **kwargs):
        self.prepare()
        qemu = self.launch_qemu(tag=vm_tag, log_suffix=str(th_index), work_path=work_dir, **kwargs)
        self.log("Launched qemu {}".format(vm_tag))
        
        self.run_qemu(qemu, func, th_index, work_dir, root, *args)
        res = qemu.alternative_func_output.get(block=True)
        self.log("Qemu {} exit".format(vm_tag))
        if len(res) == 1 and qemu.qemu_fail:
            self.case_logger.error("Error occur when reproducing {}".format(vm_tag))
            self.queue.put([[], False, True])
        else:
            self.queue.put(res)
        qemu.kill()
        
        # sleep 5 seconds to wait qemu to exit
        sleep(5)
        return
    
    def launch_qemu(self, c_hash=0, log_suffix="", log_name=None, timeout=15*60, gdb_port=None, mon_port=None, ssh_port=None, **kwargs):
        if log_name is None:
            log_name = "qemu-{0}-{1}.log".format(c_hash, self.distro_name)
        if ssh_port != None:
            self.ssh_port = ssh_port
        if gdb_port != None:
            self.gdb_port = gdb_port
        if mon_port != None:
            self.mon_port = mon_port
        qemu = VM(linux=self.path_linux, cfg=self.cfg, hash_tag=c_hash, vmlinux=self.vmlinux, port=self.ssh_port, 
            image=self.image_path, log_name=log_name, log_suffix=log_suffix, mon_port=self.mon_port, gdb_port=self.gdb_port,
            key=self.ssh_key, timeout=timeout, debug=self.debug, **kwargs)
        qemu.logger.info("QEMU-{} launched.\n".format(log_suffix))
        return qemu
    
    def run_qemu(self, qemu, func, *args):
        return qemu.run(alternative_func=func, args=(*args, ))

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
        