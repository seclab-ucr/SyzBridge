import os, shutil
import multiprocessing
import threading

from infra.tool_box import *
from plugins import AnalysisModule
from plugins.syzkaller_interface import SyzkallerInterface

syz_config_template = """
{{
        "name": "linux",
        "target": "linux/amd64/{0}",
        "http": "127.0.0.1:{1}",
        "workdir": "{2}/workdir",
        "kernel_obj": "{3}",
        "image": "{4}",
        "sshkey": "{5}",
        "syzkaller": "{2}",
        "procs": 4,
        "sandbox": "none",
        "cover": true,
        "reproduce": true,
        "enable_syscalls": [
            "openat$syz_describe_*",
            "syz_open_dev$syz_describe_*",
            "ioctl$syz_describe_*"
        ],
        "disable_syscalls": [],
        "suppressions": [],
        "ignores": [
            "hang"
        ],
        "type": "qemu",
        "vm": {{
                "count": 16,
                "cpu": 2,
                "mem": 4096,
                "kernel": "/data/yhao016/21-Template/work/latest/linux/arch/x86/boot/bzImage"
        }}
}}
"""
class SyzDescription(AnalysisModule):
    NAME = "SyzDescription"
    REPORT_START = "======================SyzDescription Report======================"
    REPORT_END =   "==================================================================="
    REPORT_NAME = "Report_SyzDescription"
    DEPENDENCY_PLUGINS = []

    def __init__(self):
        super().__init__()
        self.syz: SyzkallerInterface = None
        self.path_image = None
        self.port = None
        self.path_kernel = None
        self.ssh_key = None
        self.arch = None
        self.fuzzing_instance = None
        
    def prepare(self):
        try:
            plugin = self.cfg.get_plugin(self.NAME)
            if plugin == None:
                self.err_msg("No such plugin {}".format(self.NAME))
            self.arch = int(plugin.arch)
            self.fuzz_config = plugin.syzkaller_config
        except AttributeError:
            self.err_msg("Failed to get timeout or gdb_port or qemu_monitor_port or max_round")
            return False
        return self.prepare_on_demand()
    
    def prepare_on_demand(self):
        self._prepared = True
        return True
    
    def success(self):
        return self._move_to_success

    def run(self):
        upstream = self.cfg.get_kernel_by_name(self.kernel)
        if upstream == None:
            self.logger.exception("Fail to get {} kernel".format(self.kernel))
            return False
        self.path_image = upstream.distro_image
        self.port = upstream.repro.ssh_port
        self.path_kernel = upstream.distro_src
        self.ssh_key = upstream.ssh_key
        if self.prepare_syzkaller() != 0:
            self.err_msg("Failed to prepare syzkaller, stop fuzzing.")
            return False
        self.prepare_config()
        self.run_syzkaller()
        return True
    
    def create_snapshot(self, src, img, distro_name):
        dst = "{}/{}-snapshot.img".format(img, distro_name)
        if os.path.isfile(dst):
            os.remove(dst)
        cmd = ["qemu-img", "create", "-f", "qcow2", "-b", src, dst]
        p = Popen(cmd, stderr=STDOUT, stdout=PIPE)
        exitcode = p.wait()
        return exitcode
    
    def prepare_config(self):
        if os.path.exists(os.path.join(self.path_syzkaller, "workdir/crashes")):
            shutil.rmtree(os.path.join(self.path_syzkaller, "workdir/crashes"))

        self.create_snapshot(self.path_image, self.path_syzkaller+"/workdir", self._cur_distro.distro_name)
        self.path_image = self.path_syzkaller+"/workdir/{}-snapshot.img".format(self._cur_distro.distro_name)
        config = syz_config_template.format(self.arch, self.port, 
            self.path_syzkaller, self.path_kernel, self.path_image, 
            self.ssh_key, self.path_case_plugin)
        config_path = os.path.join("gopath/src/github.com/google/syzkaller/workdir", "my.cfg")
        self._write_to(config, config_path)
    
    def prepare_syzkaller(self):
        if self.syz == None:
            self.syz = self._init_module(SyzkallerInterface())
        self.syz.prepare_on_demand(self.path_case_plugin)
        if self.syz.pull_syzkaller() != 0:
            self.err_msg("Failed to pull syzkaller")
            return -1
        self.path_syzkaller = self.syz.syzkaller_path
        self.download_description()
        if self.syz.build_syzkaller(arch='amd64') != 0:
            self.err_msg("Failed to build syzkaller")
            return -1
        return 0
    
    def run_syzkaller(self):
        self.fuzzing_instance = multiprocessing.Process(target=self._run_syzkaller, name="syz-description")
        threading.Thread(target=self._fuzzing_monitor, name="syz-description-monitor").start()
        return

    def _fuzzing_monitor(self):
        while True:
            if not self.fuzzing_instance.is_alive():
                self.logger.info("Syzkaller fuzzing finished")
                return
            sleep(5)
        return
            
    def _run_syzkaller(self):
        syzkaller = os.path.join(self.path_syzkaller, "bin/syz-manager")
        p = Popen([syzkaller, "--config={}".format(self.fuzz_config)],
                stdout=PIPE,
                stderr=STDOUT
            )
        with p.stdout:
            log_anything(p.stdout, self.logger, self.debug)
        exitcode = p.wait()
        return exitcode
    
    def download_description(self):
        if not os.path.exists(os.path.join(self.path_case_plugin, "description")):
            local_command(command="git clone https://github.com/ZHYfeng/SyzDescribe_Syscall_Description.git description", cwd=self.path_case_plugin,
                      shell=True, logger=self.logger)
        else:
            local_command(command="git pull origin master", cwd=self.path_case_plugin,
                      shell=True, logger=self.logger)
        local_command(command="cp description/latest/* {}/sys/linux".format(self.path_syzkaller), cwd=self.path_case_plugin,
                      shell=True, logger=self.logger)
        if self.syz.update_description() != 0:
            self.err_msg("Failed to update description")
            return -1
        if self.syz.build_syzkaller(arch='amd64') != 0:
            self.err_msg("Failed to build syzkaller")
            return -1
        return 0
        
    def generate_report(self):
        final_report = "\n".join(self.report)
        self.info_msg(final_report)
        self._write_to(final_report, self.REPORT_NAME)
    
    def _write_to(self, content, name):
        file_path = "{}/{}".format(self.path_case_plugin, name)
        super()._write_to(content, file_path)

    def cleanup(self):
        super().cleanup()
