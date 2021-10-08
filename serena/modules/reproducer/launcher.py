import os, re, stat, sys
from subprocess import Popen, STDOUT, PIPE, call
import logging
import argparse
import serena.infra.tool_box as utilities
import threading
import queue
import time

from serena.infra.strings import *
from serena.modules.vm import VM

class Launcher:
    def __init__(self, case_path, ssh_port, case_logger, debug=False, qemu_num=3):
        self.case_logger = case_logger
        self.case_path = case_path
        self.image_path = "{}/ubuntu-20.04-snapshot.img".format(self.case_path)
        self.vmlinux = "{}/vmlinux".format(self.case_path)
        self.qemu_num = qemu_num
        self.ssh_port = ssh_port
        self.debug = debug
        self.kill_qemu = False
        self.queue = queue.Queue()
    
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
                self.save_crash_log(res, "ori")
                if res == []:
                    res = crashes
                break
        if len(res) == 1 and isinstance(res[0], str):
            self.logger.error(res[0])
            return [], trigger
        return res, trigger
        
    def save_crash_log(self, log, name):
        with open("{}/crash_log-{}".format(self.case_path, name), "w+") as f:
            for each in log:
                for line in each:
                    f.write(line+"\n")
                f.write("\n")
    
    def launch(self, th_index, c_hash):
        self.create_snapshot()
        qemu = VM(hash_tag=c_hash, vmlinux=self.vmlinux, port=self.ssh_port, 
            image=self.image_path, proj_path="{}/".format(self.case_path), 
            log_name="qemu-{}.log".format(c_hash), log_suffix=str(th_index),
            key="{}/id_rsa".format(self.case_path), 
            timeout=10*60, debug=self.debug)
        qemu.logger.info("QEMU-{} launched.\n".format(th_index))
        
        poc_path = os.path.join(self.case_path, "poc")
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
                        if utilities.regx_match(call_trace_regx, line) or \
                        utilities.regx_match(message_drop_regx, line):
                            record_flag = 1
                        if utilities.regx_match(boundary_regx, line) or \
                        utilities.regx_match(panic_regx, line):
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
                        if (utilities.regx_match(kasan_mem_regx, line) and 'null-ptr-deref' not in line):
                            kasan_flag = 1
                        if utilities.regx_match(write_regx, line):
                            write_flag = 1
                        if utilities.regx_match(kasan_double_free_regx, line):
                            double_free_flag = 1
                        if utilities.regx_match(read_regx, line):
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
        script = "serena/scripts/run-script.sh"
        utilities.chmodX(script)
        Popen([script, str(self.ssh_port), self.case_path],
            stderr=STDOUT,
            stdout=PIPE)
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
        dst = "{}/ubuntu-20.04-snapshot.img".format(self.case_path)
        src = "{}/tools/images/ubuntu-20.04.img".format(self.path_project)
        if os.path.isfile(dst):
            os.remove(dst)
        cmd = ["qemu-img", "create", "-f", "qcow2", "-b", src, dst]
        p = Popen(cmd, stderr=STDOUT, stdout=PIPE)
        with p.stdout:
            utilities.log_anything(p.stdout, self.case_logger, self.debug)
        exitcode = p.wait()
        return exitcode

def args_parse():
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter,
                                     description='Determine if the new crashes are from the same root cause of the old one\n'
                                                 'eg. python crash.py -i 7fd1cbe3e1d2b3f0366d5026854ee5754d451405')
    parser.add_argument('-i', '--input', nargs='?', action='store',
                        help='By default it analyze all cases under folder \'succeed\', but you can indicate a specific one.')
    parser.add_argument('--ignore', nargs='?', action='store',
                        help='A file contains cases hashs which are ignored. One line for each hash.')
    parser.add_argument('-r', '--reproduce', action='store_true',
                        help='Reproduce cases with the original testcase')
    parser.add_argument('-pm', '--parallel-max', nargs='?', action='store',
                        default='5', help='The maximum of parallel processes\n'
                        '(default valus is 5)')
    parser.add_argument('--folder', const='succeed', nargs='?', default='succeed',
                        choices=['succeed', 'completed', 'incomplete', 'error'],
                        help='Reproduce cases with the original testcase')
    parser.add_argument('--linux', nargs='?', action='store',
                        default='-1',
                        help='Indicate which linux repo to be used for running\n'
                            '(--parallel-max will be set to 1)')
    parser.add_argument('-p', '--port', nargs='?',
                        default='3777',
                        help='The default port that is used by reproducing\n'
                        '(default value is 3777)')
    parser.add_argument('--identify-by-trace', '-ibt', action='store_true',
                        help='Reproduce on fixed kernel')
    parser.add_argument('--store-read', action='store_true',
                        help='Do not ignore memory reading')
    parser.add_argument('--identify-by-patch', '-ibp', action='store_true',
                        help='Reproduce on unfixed kernel')
    parser.add_argument('--test-original-poc', action='store_true',
                        help='Reproduce with original PoC')
    parser.add_argument('--debug', action='store_true',
                        help='Enable debug mode')
    args = parser.parse_args()
    return args

if __name__ == '__main__':
    pass
        