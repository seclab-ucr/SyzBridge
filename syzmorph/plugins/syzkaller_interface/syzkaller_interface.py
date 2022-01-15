import os, logging

from infra.tool_box import chmodX, init_logger, log_anything
from plugins import AnalysisModule
from subprocess import Popen, PIPE, STDOUT, call

cfg_template = syz_config_template="""
{{ 
        "target": "linux/amd64",
        "http": "127.0.0.1:{5}",
        "workdir": "{0}/workdir",
        "kernel_obj": "{1}",
        "image": "{2}/stretch.img",
        "sshkey": "{2}/stretch.img.key",
        "syzkaller": "{0}",
        "procs": 8,
        "type": "qemu",
        "vm": {{
                "count": {4},
                "kernel": "{1}/arch/x86/boot/bzImage",
                "cpu": 2,
                "mem": 2048
        }},
        "enable_syscalls" : [
            {3}
        ]
}}"""

class SyzkallerInterface(AnalysisModule):
    NAME = "SyzkallerInterface"
    REPORT_START = "======================SyzkallerInterface Report======================"
    REPORT_END =   "==================================================================="
    REPORT_NAME = "Report_SyzkallerInterface"
    DEPENDENCY_PLUGINS = []

    def __init__(self):
        super().__init__()
        self.report = ''
        self._prepared = False
        self.path_case_plugin = ''
        self._move_to_success = False
        self.syzkaller_path = ''
        
    def prepare(self):
        return self.prepare_on_demand()
    
    def prepare_on_demand(self, plugin_path=None):
        if plugin_path is not None:
            self.path_case_plugin = plugin_path
        self._prepared = True
        return True
    
    def check_syzkaller(func):
        def inner(self, **kwargs):
            if self.syzkaller_path == '':
                self.case_logger.error("Can not find syzkaller")
                return -1
            return func(self, **kwargs)
        return inner
    
    def check_binary(self, binary_name):
        syzkaller_path = os.path.join(self.path_case_plugin, "gopath/src/github.com/google/syzkaller")
        bin_path = os.path.join(syzkaller_path, "bin")
        if self._check_binary(bin_path, binary_name):
            return True
        bin_amd64_path = os.path.join(bin_path, 'linux_amd64')
        if self._check_binary(bin_amd64_path, binary_name):
            return True
        bin_i386_path = os.path.join(bin_path, 'linux_i386')
        if self._check_binary(bin_i386_path, binary_name):
            return True
        return False
    
    def pull_syzkaller(self, commit=""):
        script_path = os.path.join(self.path_package, "plugins/syzkaller_interface/pull_syzkaller.sh")
        chmodX(script_path)
        p = Popen([script_path, self.path_case_plugin, commit], stdin=PIPE, stdout=PIPE, stderr=PIPE)
        with p.stdout:
            log_anything(p.stdout, self.logger, self.debug)
        exitcode = p.wait()
        if exitcode != 0:
            self.logger.info("Fail to generate a decent report from bug log")
        else:
            self.syzkaller_path = os.path.join(self.path_case_plugin, "gopath/src/github.com/google/syzkaller")
        return exitcode
    
    @check_syzkaller
    def build_syzkaller(self, arch="amd64", component=None):
        my_env = os.environ.copy()
        my_env["PATH"] = os.path.join(self.path_package, "tools/goroot/bin") + my_env["PATH"]
        if component == None:
            p = Popen(["make", "TARGETARCH={}".format(arch), "TARGETVMARCH=amd64"], cwd=self.syzkaller_path, env=my_env, stdin=PIPE, stdout=PIPE, stderr=PIPE)
        else:
            p = Popen(["make", "TARGETARCH={}".format(arch), "TARGETVMARCH=amd64", component], cwd=self.syzkaller_path, env=my_env, stdin=PIPE, stdout=PIPE, stderr=PIPE)
        with p.stdout:
            log_anything(p.stdout, self.logger, self.debug)
        exitcode = p.wait()
        if not os.path.exists(os.path.join(self.syzkaller_path, "workdir")):
            os.makedirs(os.path.join(self.syzkaller_path, "workdir"))
        return exitcode

    @check_syzkaller
    def patch_syzkaller(self, patch):
        p = Popen(["patch", "-p1", "-i", patch], cwd=self.syzkaller_path, stdin=PIPE, stdout=PIPE)
        with p.stdout:
            log_anything(p.stdout, self.logger, self.debug)
        exitcode = p.wait()
        return exitcode

    def delete_syzkaller(self):
        if os.path.exists(self.syzkaller_path):
            os.removedirs(self.syzkaller_path)
    
    def pull_cfg_for_cur_case(self):
        self.buil_workdir()
        linux_path = os.path.join(self.path_case, "linux")
        image_path = os.path.join(self.path_case, "img")
        syz_config = cfg_template.format(self.syzkaller_path, linux_path, image_path, "", 4, self.cfg.get_upstream().ssh_port)
        self._write_to(syz_config, "gopath/src/github.com/google/syzkaller/workdir/my.cfg")

    def buil_workdir(self):
        if not os.path.exists(os.path.join(self.syzkaller_path, "workdir")):
            os.makedirs(os.path.join(self.syzkaller_path, "workdir"))
    
    def generate_decent_report(self, input_log, output_log):
        syzkaller_workdir = os.path.join(self.path_case_plugin, "gopath/src/github.com/google/syzkaller/workdir")
        files = os.listdir(syzkaller_workdir)
        cfg_path = ""
        for each_file in files:
            if each_file.endswith('.cfg'):
                cfg_path = os.path.join(syzkaller_workdir, each_file)
                break
        syz_logparser = os.path.join(self.path_case_plugin, "gopath/src/github.com/google/syzkaller/bin/syz-logparser")
        if not os.path.isfile(syz_logparser):
            self.logger.info("Cannot find syz-logparser on current case")
            return
        cmd = [syz_logparser, "-i", input_log, "-o", output_log, "-cfg", cfg_path]
        p = Popen(cmd, stdin=PIPE, stdout=PIPE)
        with p.stdout:
            log_anything(p.stdout, logging.INFO, self.debug)
        exitcode = p.wait()
        if exitcode != 0:
            self.logger.info("Fail to generate a decent report from bug log")
        return 
    
    def success(self):
        return self._move_to_success

    def run(self):
        """
        do something
        """
        return None
    
    def generate_report(self):
        final_report = "\n".join(self.report)
        self.logger.info(final_report)
        self._write_to(final_report, self.REPORT_NAME)
    
    def _write_to(self, content, name):
        file_path = "{}/{}".format(self.path_case_plugin, name)
        super()._write_to(content, file_path)
    
    def _check_binary(self, bin, binary_name):
        if os.path.exists(bin):
            for each in os.listdir(bin):
                if os.path.isfile(os.path.join(bin, each)) and each == binary_name:
                    return True
        return False

