import os
import shutil

from infra.tool_box import *
from subprocess import Popen, PIPE, STDOUT
from plugins import AnalysisModule
from plugins.syzkaller_interface import SyzkallerInterface 
from plugins.bug_reproduce import BugReproduce

syz_config_template="""
{{ 
        "target": "linux/amd64/{0}",
        "http": "127.0.0.1:{1}",
        "workdir": "{2}/workdir",
        "kernel_obj": "{3}",
        "image": "{4}",
        "sshkey": "{5}",
        "syzkaller": "{2}",
        "procs": 8,
        "type": "qemu",
        "testcase": "{2}/workdir/testcase",
        "analyzer_dir": "{6}",
        "time_limit": "{7}",
        "store_read": true,
        "cover": false,
        "vm": {{
                "count": 4,
                "cpu": 4,
                "mem": 8096
        }},
        "enable_syscalls" : [
            {8}
        ]
}}
"""
class Fuzzing(AnalysisModule):
    NAME = "Fuzzing"
    REPORT_START = "======================Fuzzing Report======================"
    REPORT_END =   "==================================================================="
    REPORT_NAME = "Report_Fuzzing"
    DEPENDENCY_PLUGINS = ['BugReproduce']

    def __init__(self):
        super().__init__()
        self.arch = "amd64"
        self.port = None
        self.path_syzkaller = None
        self.path_image = None
        self.path_kernel = None
        self.time_limit = None
        self.syz = None
        self.enable_syscalls = []
        self._syzlang_func_regx = r'^(\w+(\$\w+)?)\('
        self._cur_distro = None
        
    def prepare(self):
        try:
            plugin = self.cfg.get_plugin(self.NAME)
            if plugin == None:
                self.err_msg("No such plugin {}".format(self.NAME))
            time_limit = int(plugin.time)
        except AttributeError:
            self.err_msg("Failed to get timeout or gdb_port or qemu_monitor_port or max_round")
            return False
        return self.prepare_on_demand(time_limit)
    
    def prepare_on_demand(self, time_limit):
        self.time_limit = time_limit
        if regx_match(r'386', self.case["manager"]):
            self.arch = "386"
        self._prepared = True
        return True
    
    def success(self):
        return self._move_to_success

    def run(self):
        br_results = None
        if self.prepare_custom_syzkaller() != 0:
            self.err_msg("Failed to prepare syzkaller, stop fuzzing.")
            return False
        self.find_support_syscalls()
        if self.plugin_finished("BugReproduce"):
            bug_reproduce = self.cfg.get_plugin(BugReproduce.NAME)
            br_results = bug_reproduce.instance.results
        else:
            self.logger.info("Bug reproduce not finished, all affected distro will run fuzzing")
        for distro in self.cfg.get_distros():
            if br_results != None:
                if br_results[distro.distro_name]['trigger']:
                    self.logger.info("{} triggers bugs, will be skipped".format(distro.distro_name))
                    continue
            self.path_image = distro.distro_image
            self.port = distro.repro.ssh_port
            self.path_kernel = distro.distro_src
            self.ssh_key = distro.ssh_key
            self._cur_distro = distro
            self.prepare_config()
            self.logger.info("===============================================")
            self.logger.info("Running fuzzing on {}".format(distro.distro_name))
            if self.run_syzkaller() != 0:
                self.main_logger.error("Failed to run syzkaller")
                return False
            self.check_output()
        return True
    
    def find_support_syscalls(self):
        dependent_syscalls = []
        testcase = request_get(self.case['syz_repro']).text
        self._write_to(testcase, "gopath/src/github.com/google/syzkaller/workdir/testcase")
        syscalls = self._extract_syscall_from_template(testcase)
        if syscalls == []:
            self.err_msg("No syscalls found in testcase: {}".format(testcase))
            return -1
        for each in syscalls:
            dependent_syscalls.extend(self._extract_all_syzlang_syscalls(each, self.path_syzkaller))
        if len(dependent_syscalls) < 1:
            self.info_msg("Cannot find dependent syscalls for\n{}\nTry to continue without them".format(testcase))
        new_syscalls = syscalls.copy()
        new_syscalls.extend(dependent_syscalls)
        new_syscalls = unique(new_syscalls)
        self.info_msg("supported syscall: {}".format(new_syscalls))
        self.enable_syscalls = "\"" + "\",\n\t\"".join(new_syscalls) + "\""

    def prepare_custom_syzkaller(self):
        patch_path = os.path.join(self.path_package, "plugins/fuzzing/syzkaller.patch")
        if self.syz == None:
            self.syz = self._init_module(SyzkallerInterface())
        self.syz.prepare_on_demand(self.path_case_plugin)
        if self.syz.pull_syzkaller(commit="b8d780ab30ab6ba340c43ad1944096dae15e6e79") != 0:
            self.err_msg("Failed to pull syzkaller")
            return -1
        if self.syz.patch_syzkaller(patch=patch_path) != 0:
            self.err_msg("Failed to patch syzkaller")
            return -1
        if self.syz.build_syzkaller('amd64') != 0:
            self.err_msg("Failed to build syzkaller")
            return -1
        self.path_syzkaller = self.syz.syzkaller_path
        return 0
    
    def prepare_config(self):
        if os.path.exists(os.path.join(self.path_syzkaller, "workdir/crashes")):
            shutil.rmtree(os.path.join(self.path_syzkaller, "workdir/crashes"))

        self.create_snapshot(self.path_image, self.path_syzkaller+"/workdir", self._cur_distro.distro_name)
        self.path_image = self.path_syzkaller+"/workdir/{}-snapshot.img".format(self._cur_distro.distro_name)
        config = syz_config_template.format(self.arch, self.port, 
            self.path_syzkaller, self.path_kernel, self.path_image, 
            self.ssh_key, self.path_case_plugin, self.time_limit, self.enable_syscalls)
        config_path = os.path.join("gopath/src/github.com/google/syzkaller/workdir", "my.cfg")
        self._write_to(config, config_path)
    
    def run_syzkaller(self):
        syzkaller = os.path.join(self.syz.syzkaller_path, "bin/syz-manager")
        p = Popen([syzkaller, "--config={}/workdir/my.cfg".format(self.syz.syzkaller_path), "--poc"],
                stdout=PIPE,
                stderr=STDOUT
            )
        with p.stdout:
            log_anything(p.stdout, self.logger, self.debug)
        exitcode = p.wait()
        return exitcode
    
    def check_output(self):
        reason = self._check_log_for_panic()
        if reason != None:
            self.main_logger.error("Fuzzing failed because of panic: {}".format(reason))
            return 
        crash_path = self._copy_crashes()
        if not os.path.exists(crash_path):
            return
        if self._cur_distro.distro_name not in self.results:
            self.results[self._cur_distro.distro_name] = []
        for crash in os.listdir(crash_path):
            subcrash_path = os.path.join(crash_path, crash)
            self.report_new_impact(subcrash_path)
    
    def report_new_impact(self, crash_path):
        if crash_path == None:
            self.err_msg("Error: crash path is None")
            return
        src_files = os.listdir(crash_path)
        for files in src_files:
            if files == "description":
                with open(os.path.join(crash_path, files), "r") as f:
                    line = f.readline()
                    self.results[self._cur_distro.distro_name].append(line)
                    self.report.append("{}: {}".format(self._cur_distro.distro_name, line))

    def create_snapshot(self, src, img, distro_name):
        dst = "{}/{}-snapshot.img".format(img, distro_name)
        if os.path.isfile(dst):
            os.remove(dst)
        cmd = ["qemu-img", "create", "-f", "qcow2", "-b", src, dst]
        p = Popen(cmd, stderr=STDOUT, stdout=PIPE)
        exitcode = p.wait()
        return exitcode
   
    def generate_report(self):
        final_report = "\n".join(self.report)
        self.info_msg(final_report)
        self._write_to(final_report, self.REPORT_NAME)
    
    def cleanup(self):
        super().cleanup()
        if self.syz != None:
            self.syz.delete_syzkaller()
    
    def _extract_syscall_from_template(self, testcase):
        res = []
        text = testcase.split('\n')
        for line in text:
            if len(line)==0 or line[0] == '#':
                continue
            syscall = regx_get(r'(\w+(\$\w+)?)\(', line, 0)
            if syscall != None:
                res.append(syscall)
        return res
    
    def _extract_all_syzlang_syscalls(self, last_syscall, syzkaller_path, search_path="sys/linux", extension=".txt"):
        res = []
        dir = os.path.join(syzkaller_path, search_path)
        if not os.path.isdir(dir):
            self.info_msg("{} do not exist".format(dir))
            return res
        for file in os.listdir(dir):
            if file.endswith(extension):
                find_it = False
                f = open(os.path.join(dir, file), "r")
                text = f.readlines()
                f.close()
                for line in text:
                    if line.find(last_syscall) != -1:
                        find_it = True
                        break

                if find_it:
                    for line in text:
                        syscall = regx_get(self._syzlang_func_regx, line, 0)
                        if syscall != None:
                            res.append(syscall)
                    break
        return res
    
    def _copy_crashes(self):
        crash_path = "{}/workdir/crashes".format(self.path_syzkaller)
        dest_path = "{}/crashes-{}".format(self.path_case_plugin, self._cur_distro.distro_name)
        i = 0
        if os.path.isdir(crash_path) and len(os.listdir(crash_path)) > 0:
            while(1):
                try:
                    shutil.copytree(crash_path, dest_path)
                    self.info_msg("Found crashes, copy them to {}".format(dest_path))
                    break
                except FileExistsError:
                    dest_path = "{}/crashes-{}".format(self.path_case_plugin, i)
                    i += 1
        return dest_path
    
    def _write_to(self, content, name):
        file_path = "{}/{}".format(self.path_case_plugin, name)
        super()._write_to(content, file_path)
    
    def _check_log_for_panic(self):
        d = {}
        disabling_func_regx = r'disabling (\w+(\$\w+)?): (.+)'
        bias_syscall_regx = r'bias to disabled syscall (\w+(\$\w+)?)'
        log_path = os.path.join(self.path_case_plugin, "log")
        with open(log_path, "r") as f:
            text = f.readlines()
            for line in text:
                if regx_match(disabling_func_regx, line):
                    func = regx_get(disabling_func_regx, line, 0)
                    reason = regx_get(disabling_func_regx, line, 2)
                    d[func] = reason
                if regx_match(bias_syscall_regx, line):
                    func = regx_get(bias_syscall_regx, line, 0)
                    return d[func]
        return None