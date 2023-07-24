import threading
import socket
import traceback
import time
import os, queue
import infra.tool_box as utilities

from time import sleep
from subprocess import Popen, PIPE, STDOUT, call

reboot_regx = r'reboot: machine restart'
port_error_regx = r'Could not set up host forwarding rule'
default_output_timer = 5

class AEmuInstance():
    ANDROID = 2

    def __init__(self, hash_tag, tag='', work_path='/tmp/', log_name='aemu.log', log_suffix="", logger=None, debug=False):
        self.work_path = work_path
        self.port = None
        self.image = None
        self.cmd_launch = None
        self.android_root = None
        self.timeout = None
        self.case_logger = None
        self.debug = debug
        self.logger = None
        self.tag = hash_tag
        self.hash_tag = hash_tag
        self.log_name = log_name
        self.alternative_func = None
        self.alternative_func_args = None
        self.alternative_func_output = None
        self.alternative_func_finished = False
        self._aemu_return = queue.Queue()
        self.aemu_ready = False
        self.kill_aemu = False
        self.trigger_crash = False
        self._shutdown = False
        self.aemu_fail = False
        self.dumped_ftrace = False
        self.output = []
        self._output_timer = default_output_timer
        self._output_lock = None
        self._reboot_once = False
        self.lock = None
        log_name += log_suffix
        self.logger = utilities.init_logger(os.path.join(work_path, log_name), debug=debug, propagate=debug)
        self.case_logger = self.logger
        self.timer = 0
        if logger != None:
            self.case_logger = logger
        if tag != '':
            self.tag = tag
        self.instance = None
        self._killed = False
    
    def log_thread(func):
        def inner(self, *args):
            self.logger.info("Start thread: {}".format(func.__name__))
            ret = func(self, *args)
            self.logger.info("Exit thread: {}".format(func.__name__))
            return ret
        return inner
        
    def reset(self):
        self.aemu_ready = False
        self.kill_aemu = False
        self.trigger_crash = False
        self._killed = False
        self.aemu_fail = False
        self.dumped_ftrace = False
        #self.aemu_ready_bar = ""
        self.output = []
        self._output_timer = default_output_timer
        self._output_lock = threading.Lock()
        self._reboot_once = False
        self.lock = threading.Lock()
        self.alternative_func_finished = False

    def setup(self, kernel, **kwargs):
        self.kernel = kernel
        if kernel.type == AEmuInstance.DISTROS:
            self.setup_distros(**kwargs)
            self.android_root = kernel.distro_image
        if kernel.type == AEmuInstance.UPSTREAM:
            pass
        return
        
    def run(self, alternative_func=None, alternative_func_output=None, args=()):
        """
        alternative_func: function to be called when aemu is ready
        args: arguments to be passed to alternative_func

        return:
            p: process of aemu
            queue: queue of alternative_func's custom output
        """
        self.reset()
        p = Popen(self.cmd_launch, stdout=PIPE, stderr=STDOUT, cwd=self.android_root)
        self.instance = p

        self.alternative_func = alternative_func
        self.alternative_func_args = args
        self.alternative_func_output = alternative_func_output

        if self.alternative_func != None and alternative_func_output == None:
            self.alternative_func_output = queue.Queue()

        x = threading.Thread(target=self.monitor_execution, name="{} aemu killer".format(self.tag))
        x.start()
        x1 = threading.Thread(target=self.__log_aemu, args=(p.stdout,), name="{} aemu logger".format(self.tag), daemon=True)
        x2 = threading.Thread(target=self._new_output_timer, name="{} aemu output timer".format(self.tag), daemon=True)
        x1.start()
        x2.start()

        return p, self.alternative_func_output
    
    def send(self, data):
        self.alternative_func_output.put(data)
    
    def _send_return_value(self, ret):
        self._aemu_return.put(ret)
    
    def recv(self, block=False, timeout=None):
        return self.alternative_func_output.get(block=block, timeout=timeout)
    
    def recvall(self):
        res = []
        while True:
            try:
                r = self.alternative_func_output.get(block=False)
                res.append(r)
            except queue.Empty:
                break
        return res
    
    def wait(self):
        ret = self._aemu_return.get(block=True)
        return ret
    
    def shutdown(self):
        self._shutdown = True
        self.command(user='root', cmds="shutdown -h now", wait=False)

    def kill_vm(self):
        self.logger.info('Kill VM pid: {}'.format(self.instance.pid))
        if self._killed:
            return
        self._killed = True
        try:
            if self._shutdown:
                n = 30
                while n > 0:
                    if self.instance.poll() == None:
                        time.sleep(1)
                        n -= 1
                    else:
                        break
            self.instance.kill()
            time.sleep(3)
        except:
            self.logger.error("VM exit abnormally")
        if self._output_lock.locked():
            self._output_lock.release()
        if self.lock.locked():
            self.lock.release()
    
    def write_cmd_to_script(self, cmd, name, build_append=False):
        path_name = os.path.join(self.work_path, name)
        with open(path_name, "w") as f:
            if build_append:
                f.write(" ".join(cmd[:-1]))
                f.write(" \"" + cmd[-1:][0] + "\"")
            else:
                f.write(" ".join(cmd))
            f.close()
    
    def upload(self, user, src: list, dst, wait: bool):
        if type(src) != str:
            self.logger.error("src must be a str")
        cmds = ["adb", "push"]
        cmds.extend([src, dst])
        self.logger.info(" ".join(cmds))
        p = Popen(cmds,
        stdout=PIPE,
        stderr=STDOUT,
        shell=True)
        with p.stdout:
            if self.logger != None:
                ret = self.log_anything(p.stdout, self.logger, self.debug)
        p.wait()
        return ret
    
    def download(self, user, src: list, dst, wait: bool):
        if type(src) != str:
            self.logger.error("src must be a str")
        cmds = ["adb", "pull"]
        cmds.extend([src, dst])
        self.logger.info(" ".join(cmds))
        p = Popen(cmds,
        stdout=PIPE,
        stderr=STDOUT,
        shell=True)
        with p.stdout:
            if self.logger != None:
                ret = self.log_anything(p.stdout, self.logger, self.debug)
        p.wait()
        return ret

    def command(self, u_cmd, user, wait: bool, timeout=None):
        ret = []
        cmds = ["adb", "shell"]
        cmds.extend(u_cmd.split(" "))
        self.logger.info(" ".join(cmds))
        p = Popen(cmds,
        stdout=PIPE,
        stderr=STDOUT,
        shell=True)
        with p.stdout:
            if self.logger != None:
                ret = self.log_anything(p.stdout, self.logger, self.debug)
        p.wait()
        return ret

    @log_thread
    def monitor_execution(self):
        booting_timer = 0
        self.timer = 0
        run_alternative_func = False
        error_count = 0
        while not self.func_finished() and (self.timeout == None or self.timer <self.timeout) and booting_timer < 180:
            if self.kill_aemu:
                self.case_logger.info('Signal kill aemu received.')
                self.kill_vm()
                return
            self.timer += 1
            if not self.aemu_ready:
                booting_timer += 1
            time.sleep(1)
            poll = self.instance.poll()
            if poll != None:
                if not self.aemu_ready:
                    self.kill_proc_by_port(self.port)
                    self.case_logger.error('aemu: Error occur at booting aemu')
                    if self.need_reboot():
                        if self._reboot_once:
                            self.case_logger.debug('aemu: Image reboot already')
                            # The image should be ready after rebooting, run instance again
                            self.run(self.alternative_func, self.alternative_func_output, self.alternative_func_args)
                            return
                        self._reboot_once = True
                        self.case_logger.error('aemu: Upstream image need a reboot')
                        break
                    self.aemu_fail = True
                if self._output_lock.locked():
                    self._output_lock.release()
                if not self.func_finished():
                    self._send_return_value(False)
                self.kill_vm()
                return
            if not self.aemu_ready and self.is_aemu_ready():
                self.aemu_ready = True
                self.timer = 0
                time.sleep(10)
                if self.alternative_func != None and not run_alternative_func:
                    x = threading.Thread(target=self._prepare_alternative_func, name="{} aemu call back".format(self.tag))
                    x.start()
                    run_alternative_func = True
        if run_alternative_func:
            self.case_logger.info('Finished alternative function, kill aemu')
        if self._reboot_once and not run_alternative_func:
            self.case_logger.debug('aemu: Try to reboot the image')
            # Disable snapshot and reboot the image
            self.kill_vm()
            self.run(self.alternative_func, self.alternative_func_output, self.alternative_func_args)
            return
        if not self.aemu_ready:
            self.aemu_fail = True
        if self.aemu_fail:
            self._send_return_value(False)
        self.kill_vm()
        return
    
    def func_finished(self):
        return self.alternative_func_finished

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
    
    # No new output in (default_output_timer) seconds
    def no_new_output(self):
        return self._output_lock.locked()
    
    def need_reboot(self):
        if self.kernel.type != AEmuInstance.UPSTREAM:
            return False
        return 'reboot: machine restart' in self.output[-1]

    def is_aemu_ready(self):
        output = self.command("uname -r", "root", wait=True, timeout=5)
        if output == None:
            self.logger.warn("aemu: SSH does not respond")
            return False
        if type(output) == list and len(output) > 0:
            for line in output:
                if utilities.regx_match(r'^\d+\.\d+', line):
                    return True
        else:
            return False
        return False

    def setup_distros(self, port, image, linux, key, mem="4G", cpu="2", gdb_port=-1, mon_port=-1, timeout=None, kasan_multi_shot=0, snapshot=True):
        #self.aemu_ready_bar = r'(\w+ login:)|(Ubuntu \d+\.\d+\.\d+ LTS ubuntu20 ttyS0)'
        self.port = port
        self.image = image
        self.key = key
        self.timeout = timeout
        self.cmd_launch = "source build/envsetup.sh && lunch sdk_phone_x86_64-en && "
        self.cmd_launch += "emulator -memory {}".format(mem)
        self.cmd_launch += "-verbose -show-kernel -selinux permissive -writable-system -no-window -no-audio -no-boot-anim"
        self.write_cmd_to_script(self.cmd_launch, "launch_{}.sh".format(self.kernel.distro_name))
    
    @log_thread
    def _prepare_alternative_func(self):
        try:
            ret = self.alternative_func(self, *self.alternative_func_args)
            self._send_return_value(ret)
        except Exception as e:
            self.logger.error("alternative_func failed: {}".format(e))
            self._send_return_value(False)
            tb = traceback.format_exc()
            self.logger.error(tb)
        self.alternative_func_finished = True
        return
    
    @log_thread
    def _new_output_timer(self):
        while not self.func_finished():
            while (self._output_timer > 0):
                self.lock.acquire()
                self._output_timer -= 1
                self.lock.release()
                if self.instance.poll() is not None:
                    return
                sleep(1)
            if self.instance.poll() is not None:
                return
            self._output_lock.acquire(blocking=True)
        #if not self._has_new_output:
        return
    
    def _resume_output_timer(self):
        self.lock.acquire()
        self._output_timer = default_output_timer
        self.lock.release()
    
    @log_thread
    def __log_aemu(self, pipe):
        try:
            self.logger.info("\n".join(self.cmd_launch)+"\n")
            self.logger.info("pid: {}  timeout: {}".format(self.instance.pid, self.timeout))
            for line in iter(pipe.readline, b''):
                self._resume_output_timer()
                if self._output_lock.locked():
                    self._output_lock.release()
                try:
                    line = line.decode("utf-8").strip('\n').strip('\r')
                except:
                    self.logger.info('bytes array \'{}\' cannot be converted to utf-8'.format(line))
                    continue
                if utilities.regx_match(reboot_regx, line) or utilities.regx_match(port_error_regx, line):
                    self.case_logger.error("Booting aemu-{} failed".format(self.log_name))
                if 'Dumping ftrace buffer' in line:
                    self.dumped_ftrace = True
                if utilities.regx_match(r'Rebooting in \d+ seconds', line):
                    self.kill_aemu = True
                self.logger.info(line)
                self.output.append(line)
        except EOFError:
            # aemu may crash and makes pipe NULL
            pass
        except ValueError:
            # Traceback (most recent call last):                                                                       │
            # File "/usr/lib/python3.6/threading.py", line 916, in _bootstrap_inner                                  │
            # self.run()                                                                                           │
            # File "/usr/lib/python3.6/threading.py", line 864, in run                                               │
            # self._target(*self._args, **self._kwargs)                                                            │
            # File "/home/xzou017/projects/SyzbotAnalyzer/syzscope/interface/vm/instance.py", line 140, in __log_aemu                                                                                                  │
            # for line in iter(pipe.readline, b''):                                                                │
            # ValueError: PyMemoryView_FromBuffer(): info->buf must not be NULL
            pass
        return
    
    def log_anything(self, pipe, logger, debug):
        output = []
        try:
            for line in iter(pipe.readline, b''):
                try:
                    line = line.decode("utf-8").strip('\n').strip('\r')
                except:
                    logger.info('bytes array \'{}\' cannot be converted to utf-8'.format(line))
                    continue
                logger.info(line)
                output.append(line)
                #if debug:
                    #print(line)
        except ValueError:
            if pipe.close:
                return output
        return output