import threading
import logging
import time
import os, queue
import infra.tool_box as utilities

from subprocess import Popen, PIPE, STDOUT, call
from .network import Network
from .error import AlternativeFunctionError

reboot_regx = r'reboot: machine restart'
port_error_regx = r'Could not set up host forwarding rule'

class VMInstance(Network):
    LTS = 0
    UBUNTU = 1
    UPSTREAM = 2

    def __init__(self, hash_tag, proj_path='/tmp/', log_name='vm.log', log_suffix="", logger=None, debug=False):
        self.proj_path = proj_path
        self.port = None
        self.image = None
        self.cmd_launch = None
        self.timeout = None
        self.case_logger = None
        self.debug = debug
        self.logger = None
        self.qemu_ready = False
        self.kill_qemu = False
        self.hash_tag = hash_tag
        self.log_name = log_name
        self.qemu_fail = False
        self.qemu_ready_bar = ""
        self.alternative_func = None
        self.alternative_func_args = None
        self.alternative_func_output = None
        self.output = []
        log_name += log_suffix
        self.logger = utilities.init_logger(os.path.join(proj_path, log_name), debug=debug, propagate=debug)
        self.case_logger = self.logger
        if logger != None:
            self.case_logger = logger
        self.instance = None
        Network.__init__(self, self.case_logger, self.debug, self.debug)

    def setup(self, type, **kwargs):
        if type == VMInstance.LTS:
            self._setup_upstream(**kwargs)
        if type == VMInstance.UBUNTU:
            self._setup_ubuntu(**kwargs)
        if type == VMInstance.UPSTREAM:
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
        if self.timeout != None:
            x = threading.Thread(target=self.monitor_execution, name="{} qemu killer".format(self.hash_tag))
            x.start()
        x1 = threading.Thread(target=self.__log_qemu, args=(p.stdout,), name="{} qemu logger".format(self.hash_tag))
        x1.start()

        self.alternative_func = alternative_func
        self.alternative_func_args = args

        if self.alternative_func != None:
            self.alternative_func_output = queue.Queue()

        return p, self.alternative_func_output

    def kill_vm(self):
        self.instance.kill()
    
    def write_cmd_to_script(self, cmd, name, build_append=False):
        path_name = os.path.join(self.proj_path, name)
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
        self.scp("localhost", user, self.port, self.key, " ".join(src), dst, True, wait)
        return
    
    def download(self, user, src: list, dst, wait: bool):
        if type(src) != list:
            self.logger.error("src must be a list")
        self.scp("localhost", user, self.port, self.key, " ".join(src), dst, False, wait)
        return

    def command(self, cmds, user, wait: bool):
        self.ssh("localhost", user, self.port, self.key, cmds, wait)
        return

    def monitor_execution(self):
        count = 0
        while (count <self.timeout/10):
            if self.kill_qemu:
                self.case_logger.info('Signal kill qemu received.')
                self.instance.kill()
                return
            count += 1
            time.sleep(10)
            poll = self.instance.poll()
            if poll != None:
                if not self.qemu_ready:
                    self.kill_proc_by_port(self.port)
                    self.case_logger.error('QEMU: Error occur at booting qemu')
                return
        self.case_logger.info('Time out, kill qemu')
        self.qemu_fail = True
        self.instance.kill()
    
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
    
    def _setup_ubuntu(self, port, image, linux, key, mem="2G", cpu="2", gdb_port=None, mon_port=None, timeout=None):
        self.qemu_ready_bar = r'(\w+ login:)|(Ubuntu \d+\.\d+\.\d+ LTS ubuntu20 ttyS0)'
        self.port = port
        self.image = image
        self.key = key
        self.timeout = timeout
        self.cmd_launch = ["qemu-system-x86_64", "-m", mem, "-smp", cpu]
        if gdb_port != None:
            self.cmd_launch.extend(["-gdb", "tcp::{}".format(gdb_port)])
        if mon_port != None:
            self.cmd_launch.extend(["-monitor", "tcp::{},server,nowait,nodelay,reconnect=-1".format(mon_port)])
        if self.port != None:
            self.cmd_launch.extend(["-net", "nic,model=e1000", "-net", "user,host=10.0.2.10,hostfwd=tcp::{}-:22".format(self.port)])
        self.cmd_launch.extend(["-display", "none", "-serial", "stdio", "-no-reboot", "-enable-kvm", "-cpu", "host,migratable=off",  
                    "-drive", "file={}".format(self.image)])
        self.write_cmd_to_script(self.cmd_launch, "launch_ubuntu.sh")
    
    def _setup_upstream(self, port, image, linux, mem="2G", cpu="2", key=None, gdb_port=None, mon_port=None, opts=None, timeout=None, kasan_multi_shot=0):
        self.qemu_ready_bar = r'Debian GNU\/Linux \d+ syzkaller ttyS\d+'
        cur_opts = ["root=/dev/sda", "console=ttyS0"]
        def_opts = ["kasan_multi_shot={}".format(kasan_multi_shot), "earlyprintk=serial", "nmi_watchdog=panic", \
                        "ftrace_dump_on_oops=orig_cpu", "rodata=n", "vsyscall=native", "net.ifnames=0", \
                        "biosdevname=0", "kvm-intel.nested=1", \
                        "kvm-intel.unrestricted_guest=1", "kvm-intel.vmm_exclusive=1", \
                        "kvm-intel.fasteoi=1", "kvm-intel.ept=1", "kvm-intel.flexpriority=1", \
                        "kvm-intel.vpid=1", "kvm-intel.emulate_invalid_guest_state=1", \
                        "kvm-intel.eptad=1", "kvm-intel.enable_shadow_vmcs=1", "kvm-intel.pml=1", \
                        "kvm-intel.enable_apicv=1"]
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
                    "-hda", "{}".format(self.image), 
                    "-snapshot", "-kernel", "{}/arch/x86_64/boot/bzImage".format(self.linux),
                    "-append"])
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
            raise AlternativeFunctionError
    
    def __log_qemu(self, pipe):
        run_alternative_func = False
        try:
            self.logger.info("\n".join(self.cmd_launch)+"\n")
            self.logger.info("pid: {}  timeout: {}".format(self.instance.pid, self.timeout))
            for line in iter(pipe.readline, b''):
                try:
                    line = line.decode("utf-8").strip('\n').strip('\r')
                except:
                    self.logger.info('bytes array \'{}\' cannot be converted to utf-8'.format(line))
                    continue
                if utilities.regx_match(reboot_regx, line) or utilities.regx_match(port_error_regx, line):
                    self.case_logger.error("Booting qemu-{} failed".format(self.log_name))
                if utilities.regx_match(self.qemu_ready_bar, line):
                    self.qemu_ready = True
                    if self.alternative_func != None and not run_alternative_func:
                        x = threading.Thread(target=self._prepare_alternative_func, name="{} qemu killer".format(self.hash_tag))
                        x.start()
                        run_alternative_func = True
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
        self.qemu_ready = False
        return