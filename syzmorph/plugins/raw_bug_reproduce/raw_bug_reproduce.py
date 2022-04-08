from audioop import reverse
import queue
import re, os, time, shutil, threading

from plugins import AnalysisModule
from modules.vm import VMInstance
from infra.tool_box import *
from infra.strings import *
from subprocess import Popen, STDOUT, PIPE, call
from plugins.modules_analysis import ModulesAnalysis
from .error import *

BUG_REPRODUCE_TIMEOUT = 5*60
MAX_BUG_REPRODUCE_TIMEOUT = 4*60*60

class RawBugReproduce(AnalysisModule):
    NAME = "RawBugReproduce"
    REPORT_START = "======================RawBugReproduce Report======================"
    REPORT_END =   "==================================================================="
    REPORT_NAME = "Report_RawBugReproduce"
    DEPENDENCY_PLUGINS = []

    FEATURE_LOOP_DEVICE = 1 << 0

    def __init__(self):
        super().__init__()
        self.report = []
        self.path_case_plugin = None
        self.bug_title = ''
        self.root_user = None
        self.normal_user = None
        self.distro_lock = threading.Lock()
        
    def prepare(self):
        if not self.manager.has_c_repro:
            self.logger.info("Case does not have c reproducer")
            return False
        try:
            plugin = self.cfg.get_plugin(self.NAME)
            if plugin == None:
                self.logger.error("No such plugin {}".format(self.NAME))
            root_user = plugin.root_user
            normal_user = plugin.normal_user
        except AttributeError:
            self.logger.error("Failed to get user name")
            return False
        return self.prepare_on_demand(root_user, normal_user)
    
    def prepare_on_demand(self, root_user, normal_user):
        self._prepared = True
        self.root_user = root_user
        self.normal_user = normal_user
        return True
    
    def check(func):
        def inner(self):
            ret = func(self)
            fail_name = ""
            for key in ret:
                if ret[key]["triggered"]:
                    title = ret[key]["bug_title"]
                    root = ret[key]["root"]
                    if not root:
                        str_privilege = " by normal user"
                    else:
                        str_privilege = " by root user"
                    self.main_logger.info("{} triggers a bug: {} {}".format(key ,title, str_privilege))
                    self.report.append("{} triggers a bug: {} {}".format(key ,title, str_privilege))
                    self._move_to_success = True
                else:
                    fail_name += key + " "
            if fail_name != "":
                self.main_logger.info("{} fail to trigger the bug".format(fail_name))
                self.report.append("{} fail to trigger the bug".format(fail_name))
            return True
        return inner

    @check
    def run(self):
        res = {}
        output = queue.Queue()
        for distro in self.cfg.get_distros():
            self.logger.info("start reproducing bugs on {}".format(distro.distro_name))
            x = threading.Thread(target=self.reproduce_async, args=(distro, output ), name="reproduce_async-{}".format(distro.distro_name))
            x.start()
            if self.debug:
                x.join()

        for _ in self.cfg.get_distros():
            [distro_name, m] = output.get(block=True)
            res[distro_name] = m
        return res
    
    def reproduce_async(self, distro, q):
        res = {}
        res["distro_name"] = distro.distro_name
        res["triggered"] = False
        res["bug_title"] = ""
        res["root"] = True
        
        success, _ = self.reproduce(distro, func=self.capture_kasan, root=True)
        if success:
            res["triggered"] = True
            res["bug_title"] = self.bug_title
            res["root"] = True
            if self.reproduce(distro, func=self.capture_kasan, root=False):
                res["triggered"] = True
                res["bug_title"] = self.bug_title
                res["root"] = False
            q.put([distro.distro_name, res])
            return
        
        q.put([distro.distro_name, res])
        return

    def reproduce(self, distro, root: bool, func, func_args=(), log_prefix= "qemu", **kwargs):
        self.distro_lock.acquire()
        poc_feature = self.tune_poc(root)
        self.distro_lock.release()
        if root:
            log_name = "{}-{}-root".format(log_prefix, distro.distro_name)
        else:
            log_name = "{}-{}-normal".format(log_prefix, distro.distro_name)
        func_args += (poc_feature,)
        distro.repro.init_logger(self.logger)
        report, triggered, t = distro.repro.reproduce(func=func, func_args=func_args, root=root, work_dir=self.path_case_plugin, vm_tag=distro.distro_name, c_hash=self.case_hash, log_name=log_name, **kwargs)
        if triggered:
            title = self._BugChecker(report)
            self.bug_title = title
            return triggered, t
        return False, t
    
    def rename_poc(self, root: bool):
        if root:
            shutil.move(os.path.join(self.path_case_plugin, "poc.c"), os.path.join(self.path_case_plugin, "poc_root.c"))
        else:
            shutil.move(os.path.join(self.path_case_plugin, "poc.c"), os.path.join(self.path_case_plugin, "poc_normal.c"))

    def tune_poc(self, root: bool):
        feature = 0

        src = os.path.join(self.path_case, "poc.c")
        if not root:
            dst = os.path.join(self.path_case_plugin, "poc_normal.c")
        else:
            dst = os.path.join(self.path_case_plugin, "poc_root.c")

        shutil.copyfile(src, dst)
        self._compile_poc(root)
        return feature
    
    def success(self):
        return self._move_to_success
    
    def generate_report(self):
        final_report = "\n".join(self.report)
        self.logger.info(final_report)
        self._write_to(final_report, self.REPORT_NAME)
    
    def capture_kasan(self, qemu, th_index, poc_path, root, poc_feature):
        self._run_poc(qemu, poc_path, root, poc_feature)
        try:
            res, trigger_hunted_bug = self._qemu_capture_kasan(qemu, th_index)
        except Exception as e:
            self.logger.error("Exception occur when reporducing crash: {}".format(e))
            if qemu.instance.poll() == None:
                qemu.instance.kill()
            res = []
            trigger_hunted_bug = False
        qemu.alternative_func_output.put([res, trigger_hunted_bug, qemu.qemu_fail], block=False)

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
                if regx_match(boundary_regx, line) or \
                regx_match(panic_regx, line):
                    if crash_flag == 1:
                        res.append(crash)
                        crash = []
                        trigger_hunted_bug = True
                        qemu.kill_qemu = True
                    record_flag = 0
                    crash_flag = 0
                    continue
                if (regx_match(kasan_mem_regx, line) and 'null-ptr-deref' not in line):
                    kasan_flag = 1
                if self._crash_start(line):
                    record_flag = 1
                if record_flag:
                    crash.append(line)
            out_begin = out_end
        return res, trigger_hunted_bug
    
    def _compile_poc(self, root: bool):
        if root:
            poc_file = "poc_root.c"
        else:
            poc_file = "poc_normal.c"
        call(["gcc", "-pthread", "-static", "-o", "poc", poc_file], cwd=self.path_case_plugin)

    def _kernel_config_pre_check(self, qemu, config):
        out = qemu.command(cmds="grep {} /boot/config-`uname -r`".format(config), user=self.root_user, wait=True)
        for line in out:
            line = line.strip()
            if line == config:
                self.logger.info("{} is enabled".format(config))
                return True
        return False

    def _run_poc(self, qemu, poc_path, root, poc_feature):
        if root:
            user = self.root_user
        else:
            user = self.normal_user
        qemu.upload(user=user, src=[poc_path], dst="~/", wait=True)
        qemu.logger.info("running PoC")
        script = os.path.join(self.path_package, "scripts/run-script.sh")
        chmodX(script)
        p = Popen([script, str(qemu.port), self.path_case_plugin, qemu.key, user],
            stderr=STDOUT,
            stdout=PIPE)
        with p.stdout:
            log_anything(p.stdout, self.logger, self.debug)
        # It looks like scp returned without waiting for all file finishing uploading.
        # Sleeping for 1 second to ensure everything is ready in vm
        time.sleep(1)
        if not self._kernel_config_pre_check(qemu, "CONFIG_KASAN=y"):
            self.logger.fatal("KASAN is not enabled in kernel!")
            raise KASANDoesNotEnabled
        qemu.command(cmds="echo \"6\" > /proc/sys/kernel/printk", user=self.root_user, wait=True)
        qemu.command(cmds="chmod +x run.sh && ./run.sh", user=user, wait=False)
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
                self.logger.error("Bug report error: {}".format(report))
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
                            self.logger.info("Double free")
                            self._write_to(self.path_project, "VendorDoubleFree")
                            flag_double_free = True
                            break
                    if regx_match(kasan_write_addr_regx, line) and not flag_kasan_write:
                            self.logger.info("KASAN MemWrite")
                            self._write_to(self.path_project, "VendorMemWrite")
                            flag_kasan_write = True
                            break
                    if regx_match(kasan_read_addr_regx, line) and not flag_kasan_read:
                            self.logger.info("KASAN MemRead")
                            self._write_to(self.path_project, "VendorMemRead")
                            flag_kasan_read = True
                            break
                    
        return title
    
    def _write_to(self, content, name):
        file_path = "{}/{}".format(self.path_case_plugin, name)
        super()._write_to(content, file_path)

