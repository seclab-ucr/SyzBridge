import threading
import logging
import time
import os, queue
import infra.tool_box as utilities

from time import sleep
from subprocess import Popen, PIPE, STDOUT, call
from .network import Network
from .error import AlternativeFunctionError

reboot_regx = r'reboot: machine restart'
port_error_regx = r'Could not set up host forwarding rule'
default_output_timer = 5

class VMInstance(Network):
    DISTROS = 0
    UPSTREAM = 1

    def __init__(self, hash_tag, tag='', work_path='/tmp/', log_name='vm.log', log_suffix="", logger=None, debug=False):
        self.work_path = work_path
        self.port = None
        self.image = None
        self.cmd_launch = None
        self.timeout = None
        self.case_logger = None
        self.debug = debug
        self.logger = None
        self.qemu_ready = False
        self.kill_qemu = False
        self.tag = hash_tag
        self.hash_tag = hash_tag
        self.log_name = log_name
        self.qemu_fail = False
        self.cfg = None
        #self.qemu_ready_bar = ""
        self.alternative_func = None
        self.alternative_func_args = None
        self.alternative_func_output = None
        self.output = []
        self._output_timer = default_output_timer
        self._output_lock = threading.Lock()
        self.lock = threading.Lock()
        log_name += log_suffix
        self.logger = utilities.init_logger(os.path.join(work_path, log_name), debug=debug, propagate=debug)
        self.case_logger = self.logger
        if logger != None:
            self.case_logger = logger
        if tag != '':
            self.tag = tag
        self.instance = None
        Network.__init__(self, self.case_logger, self.debug, self.debug)

    def setup(self, cfg, **kwargs):
        self.cfg = cfg
        if cfg.type == VMInstance.DISTROS:
            self._setup_distros(**kwargs)
        if cfg.type == VMInstance.UPSTREAM:
            self._setup_upstream(**kwargs)
        return
        
    def run(self, alternative_func=None, args=()):
        """
        alternative_func: function to be called when qemu is ready
        args: arguments to be passed to alternative_func

        return:
            p: process of qemu
            queue: queue of alternative_func's custom output
        """
        p = Popen(self.cmd_launch, stdout=PIPE, stderr=STDOUT)
        self.instance = p

        self.alternative_func = alternative_func
        self.alternative_func_args = args

        if self.alternative_func != None:
            self.alternative_func_output = queue.Queue()

        if self.timeout != None:
            x = threading.Thread(target=self.monitor_execution, name="{} qemu killer".format(self.tag))
            x.start()
        x1 = threading.Thread(target=self.__log_qemu, args=(p.stdout,), name="{} qemu logger".format(self.tag))
        x2 = threading.Thread(target=self._new_output_timer, name="{} qemu output timer".format(self.tag))
        x1.start()
        x2.start()

        return p, self.alternative_func_output

    def kill_vm(self):
        self.logger.info('Kill VM pid: {}'.format(self.instance.pid))
        try:
            self.instance.kill()
        except:
            self.logger.error("VM exit abnormally")
    
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
        if type(src) != list:
            self.logger.error("src must be a list")
        ret = self.scp("localhost", user, self.port, self.key, src, dst, True, wait)
        return ret
    
    def download(self, user, src: list, dst, wait: bool):
        if type(src) != list:
            self.logger.error("src must be a list")
        ret = self.scp("localhost", user, self.port, self.key, src, dst, False, wait)
        return ret

    def command(self, cmds, user, wait: bool, timeout=3*60):
        ret = self.ssh("localhost", user, self.port, self.key, cmds, wait, timeout)
        return ret

    def monitor_execution(self):
        qemu_failed = False
        count = 0
        run_alternative_func = False
        while (count <self.timeout):
            if self.kill_qemu:
                self.case_logger.info('Signal kill qemu received.')
                self.kill_vm()
                return
            count += 1
            time.sleep(1)
            poll = self.instance.poll()
            if poll != None:
                if not self.qemu_ready:
                    self.kill_proc_by_port(self.port)
                    self.case_logger.error('QEMU: Error occur at booting qemu')
                    self.qemu_fail = True
                    self.alternative_func_output.put([False])
                return
            if not self.qemu_ready and self.is_qemu_ready():
                self.qemu_ready = True
                count = 0
                time.sleep(10)
                if self.alternative_func != None and not run_alternative_func:
                    x = threading.Thread(target=self._prepare_alternative_func, name="{} qemu call back".format(self.tag))
                    x.start()
                    run_alternative_func = True
        self.case_logger.info('Time out, kill qemu')
        if not self.qemu_ready:
            self.qemu_fail = True
            self.alternative_func_output.put([False])
        self.kill_vm()
    
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
    
    def no_new_output(self):
        return self._output_lock.locked()
    
    def is_qemu_ready(self):
        output = self.command("uname -r", "root", wait=True, timeout=1)
        if type(output) == list and len(output) > 0:
            for line in output:
                if utilities.regx_match(r'^\d+\.\d+', line):
                    return True
        else:
            return False
        return False
    
    def _setup_distros(self, port, image, linux, key, mem="2G", cpu="2", gdb_port=None, mon_port=None, timeout=None, kasan_multi_shot=0, snapshot=True):
        #self.qemu_ready_bar = r'(\w+ login:)|(Ubuntu \d+\.\d+\.\d+ LTS ubuntu20 ttyS0)'
        self.port = port
        self.image = image
        self.key = key
        self.timeout = timeout
        self.cmd_launch = ["qemu-system-x86_64", "-m", mem, "-smp", cpu]
        #self.cmd_launch = ["/data2/xzou017/projects/qemu/qemu-6.1.0/build/qemu-system-x86_64", "-m", mem, "-smp", cpu]
        if gdb_port != None:
            self.cmd_launch.extend(["-gdb", "tcp::{}".format(gdb_port)])
        if mon_port != None:
            self.cmd_launch.extend(["-monitor", "tcp::{},server,nowait,nodelay,reconnect=-1".format(mon_port)])
        if self.port != None:
            self.cmd_launch.extend(["-net", "nic,model=e1000", "-net", "user,host=10.0.2.10,hostfwd=tcp::{}-:22".format(self.port)])
        self.cmd_launch.extend(["-display", "none", "-serial", "stdio", "-no-reboot", "-enable-kvm", "-cpu", "host,migratable=off",  
                    "-drive", "file={},format=qcow2,cache=writeback,l2-cache-size=6553600,cache-clean-interval=900".format(self.image)])
        self.write_cmd_to_script(self.cmd_launch, "launch_{}.sh".format(self.cfg.distro_name))
    
    def _setup_upstream(self, port, image, linux, mem="2G", cpu="2", key=None, gdb_port=None, mon_port=None, opts=None, timeout=None, kasan_multi_shot=0, snapshot=True):
        #self.qemu_ready_bar = r'Debian GNU\/Linux \d+ syzkaller ttyS\d+'
        cur_opts = ["root=/dev/sda", "console=ttyS0"]
        def_opts = ["earlyprintk=serial", \
                        "ftrace_dump_on_oops", "rodata=n", "vsyscall=native", "net.ifnames=0", \
                        "biosdevname=0", "kvm-intel.nested=1", \
                        "kvm-intel.unrestricted_guest=1", "kvm-intel.vmm_exclusive=1", \
                        "kvm-intel.fasteoi=1", "kvm-intel.ept=1", "kvm-intel.flexpriority=1", \
                        "kvm-intel.vpid=1", "kvm-intel.emulate_invalid_guest_state=1", \
                        "kvm-intel.eptad=1", "kvm-intel.enable_shadow_vmcs=1", "kvm-intel.pml=1", \
                        "kvm-intel.enable_apicv=1, panic_on_warn=0"]
        gdb_arg = ""
        self.port = port
        self.image = image
        self.linux = linux
        self.key = key
        self.timeout = timeout
        self.cmd_launch = ["qemu-system-x86_64", "-m", mem, "-smp", cpu]
        if gdb_port != None:
            self.cmd_launch.extend(["-gdb", "tcp::{}".format(gdb_port)])
        if mon_port != None:
            self.cmd_launch.extend(["-monitor", "tcp::{},server,nowait,nodelay".format(mon_port)])
        if self.port != None:
            self.cmd_launch.extend(["-net", "nic,model=e1000", "-net", "user,host=10.0.2.10,hostfwd=tcp::{}-:22".format(self.port)])
        self.cmd_launch.extend(["-display", "none", "-serial", "stdio", "-no-reboot", "-enable-kvm", "-cpu", "host,migratable=off", 
                    "-hda", "{}".format(self.image)])
        if snapshot:
            self.cmd_launch.append("-snapshot")
        
        self.cmd_launch.extend(["-kernel", "{}/arch/x86_64/boot/bzImage".format(self.linux), "-append"])
        if opts == None:
            cur_opts.extend(def_opts)
        else:
            cur_opts.extend(opts)
        if type(cur_opts) == list:
            self.cmd_launch.append(" ".join(cur_opts))
        self.write_cmd_to_script(self.cmd_launch, "launch_upstream.sh", build_append=True)
        return
    
    def _prepare_alternative_func(self):
        try:
            self.alternative_func(self, *self.alternative_func_args)
        except Exception as e:
            self.logger.error("alternative_func failed: {}".format(e))
            raise AlternativeFunctionError("alternative_func failed: {}".format(e))
    
    def _new_output_timer(self):
        while (self.instance.poll() is None):
            while (self._output_timer > 0):
                self.lock.acquire()
                self._output_timer -= 1
                self.lock.release()
                sleep(1)
            self._output_lock.acquire(blocking=True)
        #if not self._has_new_output:
        return
    
    def _resume_output_timer(self):
        self.lock.acquire()
        self._output_timer = default_output_timer
        self.lock.release()
    
    def __log_qemu(self, pipe):
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
                    self.case_logger.error("Booting qemu-{} failed".format(self.log_name))
                self.logger.info(line)
                self.output.append(line)
        except EOFError:
            # Qemu may crash and makes pipe NULL
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