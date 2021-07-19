import threading
import logging
import time
import os
import serena.infra.tool_box as utilities

from subprocess import Popen, PIPE, STDOUT, call
from .network import Network

reboot_regx = r'reboot: machine restart'
port_error_regx = r'Could not set up host forwarding rule'

class VMInstance(Network):
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
        self.output = []
        log_name += log_suffix
        self.logger = utilities.init_logger(os.path.join(proj_path, log_name), debug=debug, propagate=debug)
        self.case_logger = self.logger
        if logger != None:
            self.case_logger = logger
        self._qemu = None
        Network.__init__(self, self.case_logger, self.debug, self.debug)

    def setup(self, port, image, key, mem="2G", cpu="2", gdb_port=None, mon_port=None, timeout=None):
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
        self.write_cmd_to_script(self.cmd_launch, "launch_vm.sh")
        return
        
    def run(self):
        p = Popen(self.cmd_launch, stdout=PIPE, stderr=STDOUT)
        self._qemu = p
        if self.timeout != None:
            x = threading.Thread(target=self.monitor_execution, name="{} qemu killer".format(self.hash_tag))
            x.start()
        x1 = threading.Thread(target=self.__log_qemu, args=(p.stdout,), name="{} qemu logger".format(self.hash_tag))
        x1.start()

        return p

    def kill_vm(self):
        self._qemu.kill()
    
    def write_cmd_to_script(self, cmd, name):
        path_name = os.path.join(self.proj_path, name)
        with open(path_name, "w") as f:
            f.write(" ".join(cmd))
            f.close()

    def upload(self, user, src: list, dst):
        ok = self.scp("localhost", user, self.port, self.key, " ".join(src), dst)
        if ok != 0:
            self.logger.warning("scp failed: check the log for details")
        return ok

    def command(self, cmds, user='root'):
        ok = self.ssh("localhost", user, self.port, self.key, cmds)
        if ok != 0:
            self.logger.warning("ssh failed: check the log for details")
        return ok

    def monitor_execution(self):
        count = 0
        while (count <self.timeout/10):
            if self.kill_qemu:
                self.case_logger.info('Signal kill qemu received.')
                self._qemu.kill()
                return
            count += 1
            time.sleep(10)
            poll = self._qemu.poll()
            if poll != None:
                return
        self.case_logger.info('Time out, kill qemu')
        self._qemu.kill()
    
    def __log_qemu(self, pipe):
        try:
            self.logger.info("\n".join(self.cmd_launch)+"\n")
            self.logger.info("pid: {}".format(self._qemu.pid))
            for line in iter(pipe.readline, b''):
                try:
                    line = line.decode("utf-8").strip('\n').strip('\r')
                except:
                    self.logger.info('bytes array \'{}\' cannot be converted to utf-8'.format(line))
                    continue
                if utilities.regx_match(reboot_regx, line) or utilities.regx_match(port_error_regx, line):
                    self.case_logger.error("Booting qemu-{} failed".format(self.log_name))
                if utilities.regx_match(r'\w+ login:', line) or utilities.regx_match(r'Ubuntu 20.04.2 LTS ubuntu20 ttyS0', line):
                    self.qemu_ready = True
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