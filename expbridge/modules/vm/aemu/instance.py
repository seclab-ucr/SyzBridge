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
    DISTROS = 0
    UPSTREAM = 1
    ANDROID = 2

    def __init__(self, hash_tag, tag='', work_path='/tmp/', log_name='qemu.log', log_suffix="", logger=None, debug=False):
        self.work_path = work_path
        self.port = None
        self.image = None
        self.cmd_launch = None
        self.android_root = None
        self.timeout = None
        self.case_logger = None
        self.pipe_output = []
        self.debug = debug
        self.logger = None
        self.tag = hash_tag
        self.hash_tag = hash_tag
        self.log_name = log_name
        self.alternative_func = None
        self.alternative_func_args = None
        self.alternative_func_output = None
        self.alternative_func_finished = False
        self._qemu_return = queue.Queue()
        self.qemu_ready = False
        self.avd_name = "emulator-"
        self.kill_qemu = False
        self.trigger_crash = False
        self._shutdown = False
        self.qemu_fail = False
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
        self.qemu_ready = False
        self.kill_qemu = False
        self.trigger_crash = False
        self._killed = False
        self.qemu_fail = False
        self.dumped_ftrace = False
        #self.qemu_ready_bar = ""
        self.output = []
        self._output_timer = default_output_timer
        self._output_lock = threading.Lock()
        self._reboot_once = False
        self.lock = threading.Lock()
        self.alternative_func_finished = False

    def setup(self, kernel, **kwargs):
        self.kernel = kernel
        if kernel.type == AEmuInstance.ANDROID:
            self.setup_distros(**kwargs)
            self.android_root = kernel.distro_image
        else:
            pass
        return
        
    def run(self, alternative_func=None, alternative_func_output=None, args=()):
        """
        alternative_func: function to be called when qemu is ready
        args: arguments to be passed to alternative_func

        return:
            p: process of qemu
            queue: queue of alternative_func's custom output
        """
        self.reset()
        env = self._prepare_android_env()
        p = Popen(self.cmd_launch, stdout=PIPE, stderr=STDOUT, cwd=self.android_root, env=env)
        self.instance = p

        self.alternative_func = alternative_func
        self.alternative_func_args = args
        self.alternative_func_output = alternative_func_output

        if self.alternative_func != None and alternative_func_output == None:
            self.alternative_func_output = queue.Queue()

        x = threading.Thread(target=self.monitor_execution, name="{} qemu killer".format(self.tag))
        x.start()
        x1 = threading.Thread(target=self.__log_qemu, args=(p.stdout,), name="{} qemu logger".format(self.tag), daemon=True)
        x2 = threading.Thread(target=self._new_output_timer, name="{} qemu output timer".format(self.tag), daemon=True)
        x1.start()
        x2.start()

        return p, self.alternative_func_output
    
    def send(self, data):
        self.alternative_func_output.put(data)
    
    def _send_return_value(self, ret):
        self._qemu_return.put(ret)
    
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
        ret = self._qemu_return.get(block=True)
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
        cmds = "adb -s {} push ".format(self.avd_name)
        cmds += src + " "
        cmds += dst
        self.logger.info(cmds)
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
        cmds = "adb -s {} pull ".format(self.avd_name)
        cmds += src + " "
        cmds += dst
        self.logger.info(cmds)
        p = Popen(cmds,
        stdout=PIPE,
        stderr=STDOUT,
        shell=True)
        with p.stdout:
            if self.logger != None:
                ret = self.log_anything(p.stdout, self.logger, self.debug)
        p.wait()
        return ret

    def command(self, cmds, user, wait: bool, timeout=None):
        ret_queue = queue.Queue()
        x = threading.Thread(target=self._command, args=(cmds, user, ret_queue, timeout), name="ssh logger", daemon=True)
        x.start()
        if wait:
            x.join()
            try:
                pipe_output = ret_queue.get(block=False)
            except BrokenPipeError:
                return None
            return pipe_output
        return x
    
    def _command(self, u_cmd, user, ret_queue, timeout=None):
        ret = []
        cmds = "adb -s {} shell \"".format(self.avd_name)
        cmds += u_cmd
        cmds += "\""
        self.logger.info(cmds)
        p = Popen(cmds,
        stdout=PIPE,
        stderr=STDOUT,
        shell=True)
        if timeout != None:
            x = threading.Thread(target=utilities.set_timer, args=(timeout, p, ), name="ssh timer", daemon=True)
            x.start()
        else:
            # Even timeout is not set, we still launch a timer thread to monitor whether the process is still alive
            x = threading.Thread(target=utilities.set_timer, args=(-1, p, ), name="ssh timer", daemon=True)
            x.start()
        start = len(self.pipe_output)
        with p.stdout:
            if self.logger != None:
                self.log_anything(p.stdout, self.logger, self.debug)
        exitcode = p.wait()
        ret_queue.put(self.pipe_output[start:], block=False)
        return exitcode

    @log_thread
    def monitor_execution(self):
        booting_timer = 0
        self.timer = 0
        run_alternative_func = False
        error_count = 0
        while not self.func_finished() and (self.timeout == None or self.timer <self.timeout) and booting_timer < 180:
            if self.kill_qemu:
                self.case_logger.info('Signal kill qemu received.')
                self.kill_vm()
                return
            self.timer += 1
            if not self.qemu_ready:
                booting_timer += 1
            time.sleep(1)
            poll = self.instance.poll()
            if poll != None:
                if not self.qemu_ready:
                    self.kill_proc_by_port(self.port)
                    self.case_logger.error('qemu: Error occur at booting qemu')
                    if self.need_reboot():
                        if self._reboot_once:
                            self.case_logger.debug('qemu: Image reboot already')
                            # The image should be ready after rebooting, run instance again
                            self.run(self.alternative_func, self.alternative_func_output, self.alternative_func_args)
                            return
                        self._reboot_once = True
                        self.case_logger.error('qemu: Upstream image need a reboot')
                        break
                    self.qemu_fail = True
                if self._output_lock.locked():
                    self._output_lock.release()
                if not self.func_finished():
                    self._send_return_value(False)
                self.kill_vm()
                return
            if not self.qemu_ready and self.is_qemu_ready():
                self.qemu_ready = True
                self.timer = 0
                time.sleep(10)
                if self.alternative_func != None and not run_alternative_func:
                    x = threading.Thread(target=self._prepare_alternative_func, name="{} qemu call back".format(self.tag))
                    x.start()
                    run_alternative_func = True
        if run_alternative_func:
            self.case_logger.info('Finished alternative function, kill qemu')
        if self._reboot_once and not run_alternative_func:
            self.case_logger.debug('qemu: Try to reboot the image')
            # Disable snapshot and reboot the image
            self.kill_vm()
            self.run(self.alternative_func, self.alternative_func_output, self.alternative_func_args)
            return
        if not self.qemu_ready:
            self.qemu_fail = True
        if self.qemu_fail:
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

    def is_qemu_ready(self):
        output = self.command("uname -r", "root", wait=True, timeout=5)
        if output == None:
            self.logger.warn("qemu: SSH does not respond")
            return False
        if type(output) == list and len(output) > 0:
            for line in output:
                if utilities.regx_match(r'^\d+\.\d+', line):
                    return True
        else:
            return False
        return False

    def setup_distros(self, port, image, linux, key, mem="4096", cpu="2", gdb_port=-1, mon_port=-1, timeout=None, kasan_multi_shot=0, snapshot=True):
        #self.qemu_ready_bar = r'(\w+ login:)|(Ubuntu \d+\.\d+\.\d+ LTS ubuntu20 ttyS0)'
        if mem.endswith('G'):
            mem = int(mem[:-1]) * 1024
        self.port = port
        self.image = image
        self.key = key
        self.timeout = timeout
        self.cmd_launch = ["emulator"]
        self.cmd_launch.extend(["-memory", "{}".format(mem)])
        self.cmd_launch.extend(["-verbose", "-show-kernel", "-selinux", "permissive", "-writable-system", "-no-window", "-no-audio", "-no-boot-anim"])
        self.write_cmd_to_script(" ".join(self.cmd_launch), "launch_{}.sh".format(self.kernel.distro_name))
    
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
    def __log_qemu(self, pipe):
        try:
            self.logger.info(self.cmd_launch)
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
                    self.case_logger.error("Booting qemu-{} failed".format(self.log_name))
                if 'Dumping ftrace buffer' in line:
                    self.dumped_ftrace = True
                if 'Adding boot property: \'net.wifi_mac_prefix\' =' in line:
                    avd_id = utilities.regx_get(r'Adding boot property: \'net.wifi_mac_prefix\' = \'(\d+)\'', line, 0)
                    if avd_id != None:
                        self.avd_name += str(avd_id)
                    else:
                        self.logger.error("Fail to obtain the avd id")
                if utilities.regx_match(r'Rebooting in \d+ seconds', line):
                    self.kill_qemu = True
                self.logger.info(line)
                self.output.append(line)
        except EOFError:
            # qemu may crash and makes pipe NULL
            pass
        except ValueError:
            # Traceback (most recent call last):                                                                       │
            # File "/usr/lib/python3.6/threading.py", line 916, in _bootstrap_inner                                  │
            # self.run()                                                                                           │
            # File "/usr/lib/python3.6/threading.py", line 864, in run                                               │
            # self._target(*self._args, **self._kwargs)                                                            │
            # File "/home/xzou017/projects/SyzbotAnalyzer/syzscope/interface/vm/instance.py", line 140, in __log_qemu                                                                                                  │
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
                self.pipe_output.append(line)
                output.append(line)
                #if debug:
                    #print(line)
        except ValueError:
            if pipe.close:
                return output
        return output
    
    def _prepare_android_env(self):
        env = os.environ.copy()
        env["PATH"] = "{0}/prebuilts/jdk/jdk11/linux-x86/bin:"\
            "{0}/out/soong/host/linux-x86/bin:"\
            "{0}/out/host/linux-x86/bin:"\
            "{0}/prebuilts/gcc/linux-x86/x86/x86_64-linux-android-4.9/bin:"\
            "{0}/development/scripts:"\
            "{0}/prebuilts/devtools/tools:"\
            "{0}/external/selinux/prebuilts/bin:"\
            "{0}/prebuilts/misc/linux-x86/dtc:"\
            "{0}/prebuilts/misc/linux-x86/libufdt:"\
            "{0}/prebuilts/clang/host/linux-x86/llvm-binutils-stable:"\
            "{0}/prebuilts/android-emulator/linux-x86_64:"\
            "{0}/prebuilts/asuite/acloud/linux-x86:"\
            "{0}/prebuilts/asuite/aidegen/linux-x86:"\
            "{0}/prebuilts/asuite/atest/linux-x86:".format(self.android_root) + env["PATH"]
        env["TARGET_BUILD_APPS"] = ""
        env["TARGET_PRODUCT"] = "sdk_phone_x86_64"
        env["TARGET_BUILD_VARIANT"] = "eng"
        env["TARGET_BUILD_TYPE"] = "release"
        env["TARGET_GCC_VERSION"] = "4.9"
        env["ANDROID_TOOLCHAIN"] = "{0}/prebuilts/gcc/linux-x86/x86/x86_64-linux-android-4.9/bin".format(self.android_root)
        env["ANDROID_TOOLCHAIN_2ND_ARCH"] = ""
        env["ANDROID_DEV_SCRIPTS"] = "{0}/development/scripts:{0}/prebuilts/devtools/tools:{0}/external/selinux/prebuilts/bin:{0}/prebuilts/misc/linux-x86/dtc:{0}/prebuilts/misc/linux-x86/libufdt".format(self.android_root)
        env["ASAN_SYMBOLIZER_PATH"] = "{0}/prebuilts/clang/host/linux-x86/llvm-binutils-stable/llvm-symbolizer".format(self.android_root)
        env["ANDROID_EMULATOR_PREBUILTS"] = "{0}/prebuilts/android-emulator/linux-x86_64".format(self.android_root)
        env["ANDROID_BUILD_PATHS"] = "{0}/out/soong/host/linux-x86/bin:{0}/out/host/linux-x86/bin:{0}/prebuilts/gcc/linux-x86/x86/x86_64-linux-android-4.9/bin:{0}/development/scripts:{0}/prebuilts/devtools/tools:{0}/external/selinux/prebuilts/bin:{0}/prebuilts/misc/linux-x86/dtc:{0}/prebuilts/misc/linux-x86/libufdt:{0}/prebuilts/clang/host/linux-x86/llvm-binutils-stable:{0}/prebuilts/android-emulator/linux-x86_64:{0}/prebuilts/asuite/acloud/linux-x86:{0}/prebuilts/asuite/aidegen/linux-x86:{0}/prebuilts/asuite/atest/linux-x86:".format(self.android_root)
        env["PYTHONPATH"] = "{0}/development/python-packages:".format(self.android_root)
        env["ANDROID_PYTHONPATH"] = "{0}/development/python-packages:".format(self.android_root)
        env["ANDROID_JAVA_HOME"] = "{0}/prebuilts/jdk/jdk11/linux-x86".format(self.android_root)
        env["JAVA_HOME"] = "{0}/prebuilts/jdk/jdk11/linux-x86".format(self.android_root)
        env["ANDROID_JAVA_TOOLCHAIN"] = "{0}/prebuilts/jdk/jdk11/linux-x86/bin".format(self.android_root)
        env["ANDROID_PRE_BUILD_PATHS"] = "{0}/prebuilts/jdk/jdk11/linux-x86/bin:".format(self.android_root)
        env["ANDROID_PRODUCT_OUT"] = "{0}/out/target/product/emulator_x86_64".format(self.android_root)
        env["OUT"] = "{0}/out/target/product/emulator_x86_64".format(self.android_root)
        env["ANDROID_HOST_OUT"] = "{0}/out/host/linux-x86".format(self.android_root)
        env["ANDROID_SOONG_HOST_OUT"] = "{0}/out/soong/host/linux-x86".format(self.android_root)
        env["ANDROID_HOST_OUT_TESTCASES"] = "{0}/out/host/linux-x86/testcases".format(self.android_root)
        env["ANDROID_TARGET_OUT_TESTCASES"] = "{0}/out/target/product/emulator_x86_64/testcases".format(self.android_root)
        env["BUILD_ENV_SEQUENCE_NUMBER"] = "13"
        env["ANDROID_BUILD_TOP"] = "{0}".format(self.android_root)
        return env