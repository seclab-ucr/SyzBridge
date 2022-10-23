import os, logging
import shutil, time
from xml.etree.ElementTree import SubElement

from .error import CloneKernelFailed
from infra.tool_box import *
from infra.config.vendor import Vendor
from plugins import AnalysisModule

class LtsReproduce(AnalysisModule):
    NAME = "LtsReproduce"
    REPORT_START = "======================LtsReproduce Report======================"
    REPORT_END =   "==================================================================="
    REPORT_NAME = "Report_LtsReproduce"
    DEPENDENCY_PLUGINS = []

    def __init__(self):
        super().__init__()
        self.bug_title = None
        self.repro_timeout = None
        
    def prepare(self):
        try:
            plugin = self.cfg.get_plugin(self.NAME)
            if plugin == None:
                self.err_msg("No such plugin {}".format(self.NAME))
            self.repro_timeout = int(plugin.timeout)
        except AttributeError:
            self.err_msg("Failed to get timeout")
            return False
        return self.prepare_on_demand()
    
    def prepare_on_demand(self):
        self._prepared = True
        return True
    
    def success(self):
        return self._move_to_success

    def run(self):
        """
        do something
        True: plugin runs smoothly
        False: something failed, stamp will not be created
        """
        for distro in self.cfg.get_distros():
            lts_version, commit = self.get_lts_info(distro)
            #self.build_lts_kernel(lts_version, commit)
            self.logger.info("Reproducing LTS {} from {}".format(lts_version, distro.distro_name))
            ret = self.reproduce()
            self.results[distro.distro_name] = {}
            self.results[distro.distro_name]['trigger'] = ret
            if ret:
                self.results[distro.distro_name]['title'] = self.bug_title
                self.report.append("LTS kernel {}(commit:{}) reproduces this bug: {}".format(lts_version, commit, self.bug_title))
            else:
                self.results[distro.distro_name]['title'] = ""
                self.logger.info("LTS kernel {}(commit:{}) cannot reproduce this bug".format(lts_version, commit))
        return True
    
    def get_lts_info(self, distro: Vendor):
        repo_path = self._check_lts_repo()
        major_version = regx_get(r'^(\d+\.\d+)', distro.distro_version, 0)
        
        out = local_command(command="git log origin/linux-{}.y --oneline --grep \"Linux {}\" -1 | awk '{{print $1}}'".format(major_version, distro.distro_version),
                            cwd=repo_path, shell=True)
        for line in out:
            line = line.strip()
            if line != "":
                cur_commit = line
        if cur_commit == None:
            self.logger.error("Fail to get current commit for {}".format(distro.distro_version))
            return False

        self.logger.info("{}({}) equals to LTS commit {}".format(distro.distro_name, distro.distro_version, cur_commit))
        return "linux-{}.y".format(major_version), cur_commit
    
    def build_lts_kernel(self, lts_version, commit):
        branch="origin/{}".format(lts_version)
        return self.build_mainline_kernel(kernel=lts_version, commit=commit, branch=branch, keep_ori_config=True)
    
    def reproduce(self):
        lts_kernel = self.cfg.get_kernel_by_name('stable')
        success, _ = self._reproduce(lts_kernel, func=self.capture_kasan, root=True, timeout=self.repro_timeout, logger=self.logger)
        return success

    def tune_poc(self, root):
        src = os.path.join(self.path_case, "poc.c")
        if not root:
            dst = os.path.join(self.path_case_plugin, "poc_normal.c")
        else:
            dst = os.path.join(self.path_case_plugin, "poc_root.c")

        shutil.copyfile(src, dst)
        #self._compile_poc(root)
        return

    def _reproduce(self, distro, root: bool, func, func_args=(), log_prefix= "qemu", **kwargs):
        if root:
            self.set_stage_text("\[root] Booting {}".format(distro.distro_name))
        else:
            self.set_stage_text("\[user] Booting {}".format(distro.distro_name))

        self.tune_poc(root)
        if root:
            log_name = "{}-{}-root".format(log_prefix, distro.distro_name)
        else:
            log_name = "{}-{}-normal".format(log_prefix, distro.distro_name)
        distro.repro.init_logger(self.logger)
        self.root_user = distro.repro.root_user
        self.normal_user = distro.repro.normal_user
        
        report, triggered, t = distro.repro.reproduce(func=func, func_args=func_args, root=root, work_dir=self.path_case_plugin, vm_tag=distro.distro_name, c_hash=self.case_hash, log_name=log_name, **kwargs)
        self.info_msg("{} triggered bugs: {}".format(distro.distro_name, triggered))
        if triggered:
            title = self._BugChecker(report)
            self.bug_title = title
            return triggered, t
        return False, t

    def capture_kasan(self, qemu, th_index, work_dir, root):
        if root:
            self.set_stage_text("\[root] Reproducing on {}".format(qemu.tag))
        else:
            self.set_stage_text("\[user] Reproducing on {}".format(qemu.tag))

        self._run_poc(qemu, work_dir, root)
        try:
            res, trigger_hunted_bug = self._qemu_capture_kasan(qemu, th_index)
        except Exception as e:
            self.err_msg("Exception occur when reporducing crash: {}".format(e))
            if qemu.instance.poll() == None:
                qemu.instance.kill()
            res = []
            trigger_hunted_bug = False
        return [res, trigger_hunted_bug, qemu.qemu_fail]
    
    def _crash_start(self, line):
        crash_head = [r'BUG: ', r'WARNING:', r'INFO:', r'Unable to handle kernel', 
                r'general protection fault', r'stack segment:', r'kernel BUG',
                r'BUG kmalloc-', r'divide error:', r'divide_error:', r'invalid opcode:',
                r'UBSAN:', r'unregister_netdevice: waiting for', r'Internal error:',
                r'Unhandled fault:', r'Alignment trap:']

        for each in crash_head:
            if regx_match(each, line):
                return True
        return False
    
    def _qemu_capture_kasan(self, qemu, th_index):
        qemu_close = False
        out_begin = 0
        record_flag = 0
        crash_flag = 0
        kasan_flag = 0
        crash = []
        res = []
        trigger_hunted_bug = False
        while not qemu_close:
            if qemu.instance.poll() != None:
                qemu_close = True
            out_end = len(qemu.output)
            for line in qemu.output[out_begin:]:
                if regx_match(call_trace_regx, line) or \
                regx_match(message_drop_regx, line):
                    crash_flag = 1
                if (regx_match(boundary_regx, line) and record_flag) or \
                        regx_match(panic_regx, line) or \
                        (self._crash_start(line) and crash_flag):
                    if crash_flag == 1:
                        res.append(crash)
                        crash = []
                        trigger_hunted_bug = True
                        qemu.kill_qemu = True
                    record_flag = 0
                    crash_flag = 0
                    continue
                if self._crash_start(line):
                    record_flag = 1
                    crash_flag = 0
                    crash = []
                if record_flag:
                    crash.append(line)
            out_begin = out_end
        return res, trigger_hunted_bug
    
    def _run_poc(self, qemu, work_dir, root):
        if root:
            user = self.root_user
            poc_src = "poc_root.c"
        else:
            user = self.normal_user
            poc_src = "poc_normal.c"
        poc_path = os.path.join(work_dir, poc_src)
        qemu.upload(user=user, src=[poc_path], dst="~/", wait=True)
        if '386' in self.case['manager']:
            qemu.command(cmds="gcc -m32 -pthread -o poc {}".format(poc_src), user=user, wait=True)
        else:
            qemu.command(cmds="gcc -pthread -o poc {}".format(poc_src), user=user, wait=True)
        qemu.logger.info("running PoC")
        # It looks like scp returned without waiting for all file finishing uploading.
        # Sleeping for 1 second to ensure everything is ready in vm
        time.sleep(1)
        qemu.command(cmds="echo \"6\" > /proc/sys/kernel/printk", user=self.root_user, wait=True)
        qemu.command(cmds="chmod +x poc && ./poc", user=user, wait=False)
        return

    def _check_lts_repo(self):
        work_path = os.getcwd()
        first_stable_linux_repo = os.path.join(work_path, "tools/linux-stable-0")
        stable_linux_repo = os.path.join(work_path, "tools/linux-stable-{}".format(self.index))
        if not os.path.exists(stable_linux_repo):
            if not os.path.exists(first_stable_linux_repo):
                self._clone_stable_linux_repo(first_stable_linux_repo)
            shutil.copytree(first_stable_linux_repo, stable_linux_repo)
        return stable_linux_repo
    
    def _clone_stable_linux_repo(self, repo_path):
        cwd = os.path.dirname(repo_path)
        self.logger.info("Cloning stable linux repo")
        local_command(command="git clone https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git {}".format(repo_path),
                      cwd=cwd, shell=True, logger=self.logger)
        if not os.path.exists(repo_path):
            raise CloneKernelFailed("linux-stable")
        return
    
    def _BugChecker(self, report):
        title = None
        flag_double_free = False
        flag_kasan_write = False
        flag_kasan_read = False
        if report != []:
            try:
                title = report[0][0]
            except IndexError:
                self.err_msg("Bug report error: {}".format(report))
                return None
            if regx_match(r'\[(( )+)?\d+\.\d+\] (.+)', title):
                title = regx_get(r'\[(( )+)?\d+\.\d+\] (.+)', title, 2)
            for each in report:
                for line in each:
                    if regx_match(r'BUG: (KASAN: [a-z\\-]+ in [a-zA-Z0-9_]+)', line) or \
                        regx_match(r'BUG: (KASAN: double-free or invalid-free in [a-zA-Z0-9_]+)', line):
                        m = re.search(r'BUG: (KASAN: [a-z\\-]+ in [a-zA-Z0-9_]+)', line)
                        if m != None and len(m.groups()) > 0:
                            title = m.groups()[0]
                        m = re.search(r'BUG: (KASAN: double-free or invalid-free in [a-zA-Z0-9_]+)', line)
                        if m != None and len(m.groups()) > 0:
                            title = m.groups()[0]
                    if regx_match(double_free_regx, line) and not flag_double_free:
                            self.info_msg("Double free")
                            self._write_to(self.path_project, "VendorDoubleFree")
                            flag_double_free = True
                            break
                    if regx_match(kasan_write_addr_regx, line) and not flag_kasan_write:
                            self.info_msg("KASAN MemWrite")
                            self._write_to(self.path_project, "VendorMemWrite")
                            flag_kasan_write = True
                            break
                    if regx_match(kasan_read_addr_regx, line) and not flag_kasan_read:
                            self.info_msg("KASAN MemRead")
                            self._write_to(self.path_project, "VendorMemRead")
                            flag_kasan_read = True
                            break
                    
        return title
    
    def generate_report(self):
        final_report = "\n".join(self.report)
        self.info_msg(final_report)
        self._write_to(final_report, self.REPORT_NAME)
    
    def _write_to(self, content, name):
        file_path = "{}/{}".format(self.path_case_plugin, name)
        super()._write_to(content, file_path)

    def cleanup(self):
        super().cleanup()
