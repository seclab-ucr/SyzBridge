import multiprocessing
import threading
import queue

from time import sleep

from infra.strings import *
from infra.tool_box import *
from subprocess import Popen, PIPE, call
from modules.vm import VM
from .build import Build
from .error import KASANDoesNotEnabled

qemu_output_window = 15

class Launcher(Build):
    def __init__(self, kernel_cfg, manager):
        Build.__init__(self, kernel_cfg, manager)
        self.manager = manager
        self.case_logger = manager.case_logger
        self.debug = manager.debug
        self.queue = multiprocessing.Queue()
        self.crash_head = [r'BUG: unable to handle'
                r'general protection fault', r'KASAN:',
                r'BUG: kernel NULL pointer dereference']
        self.crash_tail = [r'------------\[ cut here \]------------',
                    r'---\[ end trace [a-zA-Z0-9]+ \]---',
                    r'Rebooting in \d+ seconds..',
                    r'Kernel panic']
        self._setup_crash_capturer()
        
    def save_crash_log(self, log_msg, name):
        with open("{}/crash_log-{}".format(self.path_case, name), "w+") as f:
            for each in log_msg:
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
    
    def reproduce(self, func, func_args, work_dir, timeout, vm_tag="reproducer", root=True, attempt=3, **kwargs):
        res = []
        trigger = False
        ever_success = False
        remain = []
        
        i = 0
        error_attempt = 0
        while i < attempt:
            args = {'th_index':i, 'func':func, 'args':func_args, 'root':root, 'work_dir':work_dir, 'vm_tag':vm_tag + '-' + str(i), 'timeout':timeout, **kwargs}
            x = multiprocessing.Process(target=self._reproduce, kwargs=args, name="{}-{} trigger-{}".format(self.manager.case_hash, self.kernel.distro_name, i))
            x.start()
            self.log("Start reproducing {} in process {}, args {}".format(vm_tag + '-' + str(i), x.pid, args))
            
            t = self.queue.get(block=True)
            if len(t) >= 3:
                crashes = t[0]
                high_risk = t[1] 
                qemu_fail = t[2]
                if len(t) > 3:
                    remain = t[3:]
                self.log("Reproducing done, crashes: {}, high_risk {}, qemu_fail {}".format(crashes, high_risk, qemu_fail))
                if qemu_fail:
                    error_attempt += 1
                    if error_attempt > 3:
                        break
                    continue
            else:
                error_attempt += 1
                self.log("Reproducing failed, ret {}".format(t))
                if error_attempt > 3:
                    break
                continue
            i += 1
            if not trigger and crashes != []:
                trigger = True
                res = crashes
                self.save_crash_log(res, self.distro_name)
                if res == []:
                    res = crashes
                break
        if len(res) == 1 and isinstance(res[0], str):
            self.case_logger.error(res[0])
            return [], trigger, remain
        return res, trigger, remain
    
    def _reproduce(self, th_index, func, args, root, work_dir, vm_tag, timeout, **kwargs):
        self.log("New Process for reproducing {}".format(vm_tag))
        self.prepare()
        qemu = self.launch_qemu(tag=vm_tag, log_suffix=str(th_index), work_path=work_dir, timeout=timeout, **kwargs)
        self.log("Launched qemu {}".format(vm_tag))
        
        self.run_qemu(qemu, self._capture_crash, th_index, work_dir, root, timeout, func, *args)
        res = qemu.wait()
        self.log("Qemu {} exit".format(vm_tag))
        if type(res) == bool or (len(res) == 1 and qemu.qemu_fail):
            self.case_logger.error("Error occur when reproducing {}".format(vm_tag))
            self.queue.put([[], False, True])
        else:
            self.queue.put(res)
        qemu.destroy()
        
        # sleep 5 seconds to wait qemu to exit
        sleep(5)
        return
    
    def warp_qemu_capture_crash(self, qemu, q):
        try:
            res, trigger_hunted_bug = self._qemu_capture_crash(qemu)
        except Exception as e:
            self.logger.error("Exception occur when reporducing crash: {}".format(e))
            if qemu.instance.poll() == None:
                qemu.instance.kill()
            res = []
            trigger_hunted_bug = False
        # There might be a race condition in between _qemu_capture_kasan and tweak_modules
        # the queue 'q' put data after lock was released, tweak_modules has chance that assume
        # the queue is empty and no new output comes out of QEMU and thus have a wrong module
        # The race window is relatively small, I choose to ignore it to keep our function design
        # Will solve this problem if this race happens in real world
        q.put([res, trigger_hunted_bug])
        return
    
    def _crash_start(self, line):
        for each in self.crash_head:
            if regx_match(each, line):
                return True
        return False
    
    def _crash_end(self, line):
        for each in self.crash_tail:
            if regx_match(each, line):
                return True
        return False

    def _qemu_capture_crash(self, qemu: VM):
        qemu_close = False
        out_begin = 0
        record_flag = 0
        crash_flag = 0
        crash = []
        res = []
        trigger_hunted_bug = False
        while not qemu_close:
            if qemu.instance.poll() != None:
                qemu_close = True
            out_end = len(qemu.output)
            for line in qemu.output[out_begin:]:
                if regx_match(boundary_regx, line) or \
                        self._crash_start(line):
                    record_flag ^= 1
                    if crash_flag == 1 and crash != []:
                        res.append(crash)
                        crash = []
                        trigger_hunted_bug = True
                        qemu.kill_qemu = True
                        qemu.trigger_crash = True
                        break
                    crash_flag = 0
                if regx_match(call_trace_regx, line) or \
                regx_match(message_drop_regx, line):
                    crash_flag = 1
                if record_flag:
                    crash.append(line)
                if (regx_match(boundary_regx, line) and record_flag) or \
                    self._crash_end(line) or \
                    (self._crash_start(line) and crash_flag):
                    if crash_flag == 1 and crash != []:
                        res.append(crash)
                        crash = []
                        trigger_hunted_bug = True
                        qemu.kill_qemu = True
                        qemu.trigger_crash = True
                        break
                    record_flag = 0
                    crash_flag = 0
                    continue
            out_begin = out_end
        return res, trigger_hunted_bug
    
    def _kernel_config_pre_check(self, qemu, config):
        out = qemu.command(cmds="ls /boot/config-`uname -r`".format(config), user=self.root_user, wait=True)
        if 'No such file or directory' in out[1]:
            # If no config file found, normally it's upstream kernel
            return True
        out = qemu.command(cmds="grep {} /boot/config-`uname -r`".format(config), user=self.root_user, wait=True)
        for line in out:
            line = line.strip()
            if line == config:
                self.logger.info("{} is enabled".format(config))
                return True
        return False
    
    def _wrap_main_func(self, main_func_q, func, *args):
        ret = func(*args)
        main_func_q.put(ret)
        return

    def _setup_crash_capturer(self):
        try:
            head = self.kernel.crash_head
            self.crash_head = head
        except AttributeError:
            pass
    
        try:
            tail = self.kernel.crash_tail
            self.crash_head = tail
        except AttributeError:
            pass
        return

    def _capture_crash(self, qemu, th_index, work_dir, root, timeout, func, *args):
        qemu_queue = queue.Queue()
        threading.Thread(target=self.warp_qemu_capture_crash, args=(qemu, qemu_queue), name="qemu_crash_capturer", daemon=True).start()
        """"
        if not self._kernel_config_pre_check(qemu, "CONFIG_KASAN=y"):
            self.logger.fatal("KASAN is not enabled in kernel!")
            raise KASANDoesNotEnabled(qemu.tag)
        """
        
        main_func_q = queue.Queue()
        main = threading.Thread(target=self._wrap_main_func, args=(main_func_q, func, qemu, root,) + args, daemon=True)
        main.start()

        n = int(timeout/qemu_output_window)
        for _ in range(0, n):
            try:
                [res, trigger] = qemu_queue.get(block=True, timeout=qemu_output_window)
                if trigger:
                    try:
                        main_ret = main_func_q.get(block=True, timeout=10)
                    except queue.Empty:
                        self.logger.error("crash capturer has finished {} seconds routine but PoC is still running ")
                        main_ret = None
                    self.logger.info("Reproduce finished, triggered the bug")
                    return [res, trigger, qemu.qemu_fail, main_ret]
            except queue.Empty:
                if qemu.no_new_output() and not main.is_alive() and not qemu.trigger_crash:
                    break
        try:
            main_ret = main_func_q.get(block=True, timeout=10)
        except queue.Empty:
            self.logger.error("crash capturer has finished {} seconds routine but PoC is still running ")
            main_ret = None
        self.logger.info("Reproduce finished, didn't trigger bug")
        return [[], False, qemu.qemu_fail, main_ret]
    
    def launch_qemu(self, c_hash=0, log_suffix="", log_name=None, timeout=None, gdb_port=None, mon_port=None, ssh_port=None, **kwargs):
        if log_name is None:
            log_name = "qemu-{0}-{1}.log".format(c_hash, self.distro_name)
        if ssh_port != None:
            self.ssh_port = ssh_port
        qemu = VM(linux=self.path_linux, kernel=self.kernel, hash_tag=c_hash, vmlinux=self.vmlinux, port=self.ssh_port, 
            image=self.image_path, log_name=log_name, log_suffix=log_suffix,
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
        