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
        self.bug_title = ''
        self.root_user = None
        self.normal_user = None
        self.distro_lock = threading.Lock()
        self.repro_timeout = BUG_REPRODUCE_TIMEOUT
        
    def prepare(self):
        self._init_results()
        try:
            plugin = self.cfg.get_plugin(self.NAME)
            if plugin == None:
                self.err_msg("No such plugin {}".format(self.NAME))
            self.repro_timeout = int(plugin.timeout)
        except AttributeError:
            self.err_msg("Failed to get timeout")
            return False
        if not self.manager.has_c_repro:
            self.info_msg("Case does not have c reproducer")
            return False
        return self.prepare_on_demand()
    
    def prepare_on_demand(self):
        self._prepared = True
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
                    self.set_stage_text("Triggered")
                    self._move_to_success = True
                else:
                    fail_name += key + " "
            if fail_name != "":
                self.main_logger.info("{} fail to trigger the bug".format(fail_name))
                self.report.append("{} fail to trigger the bug".format(fail_name))
                self.set_stage_text("Failed")
            return True
        return inner

    @check
    def run(self):
        res = {}
        output = queue.Queue()
        for distro in self.cfg.get_distros():
            self.info_msg("start reproducing bugs on {}".format(distro.distro_name))
            x = threading.Thread(target=self.reproduce_async, args=(distro, output ), name="{} reproduce_async-{}".format(self.case_hash, distro.distro_name))
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
        
        success, _ = self.reproduce(distro, func=self.capture_kasan, root=True, timeout=self.repro_timeout)
        if success:
            res["triggered"] = True
            res["bug_title"] = self.bug_title
            res["root"] = True
            success, _ = self.reproduce(distro, func=self.capture_kasan, root=False, timeout=self.repro_timeout)
            if success:
                res["triggered"] = True
                res["bug_title"] = self.bug_title
                res["root"] = False
            self.results[distro.distro_name]['root'] = res['root']
            self.results[distro.distro_name]['trigger'] = True
            q.put([distro.distro_name, res])
            return
        
        q.put([distro.distro_name, res])
        return

    def reproduce(self, distro, root: bool, func, func_args=(), log_prefix= "qemu", **kwargs):
        if root:
            self.set_stage_text("\[root] Booting {}".format(distro.distro_name))
        else:
            self.set_stage_text("\[user] Booting {}".format(distro.distro_name))

        self.distro_lock.acquire()
        poc_feature = self.tune_poc(root)
        self.distro_lock.release()
        if root:
            log_name = "{}-{}-root".format(log_prefix, distro.distro_name)
        else:
            log_name = "{}-{}-normal".format(log_prefix, distro.distro_name)
        func_args += (poc_feature,)
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

    def tune_poc(self, root: bool):
        feature = 0

        src = os.path.join(self.path_case, "poc.c")
        if not root:
            dst = os.path.join(self.path_case_plugin, "poc_normal.c")
        else:
            dst = os.path.join(self.path_case_plugin, "poc_root.c")

        shutil.copyfile(src, dst)
        #self._compile_poc(root)
        return feature
    
    def success(self):
        for key in self.results:
            if self.results[key]['trigger']:
                return True
        return False
    
    def generate_report(self):
        final_report = "\n".join(self.report)
        self.info_msg(final_report)
        self._write_to(final_report, self.REPORT_NAME)
    
    def _update_qemu_timer_status(self, index, qemu):
        while True:
            if qemu.instance.poll() != None:
                break
            self.set_stage_status("[{}/3] {}/{}".format(index, qemu.timer, qemu.timeout))
            time.sleep(5)

    def capture_kasan(self, qemu, th_index, work_dir, root, poc_feature):
        if root:
            self.set_stage_text("\[root] Reproducing on {}".format(qemu.tag))
        else:
            self.set_stage_text("\[user] Reproducing on {}".format(qemu.tag))
        threading.Thread(target=self._update_qemu_timer_status, args=(th_index, qemu), name="update_qemu_timer_status").start()

        if not self._kernel_config_pre_check(qemu, "CONFIG_KASAN=y"):
            self.logger.fatal("KASAN is not enabled in kernel!")
            raise KASANDoesNotEnabled(self.case_hash)
        self._run_poc(qemu, work_dir, root, poc_feature)
        try:
            res, trigger_hunted_bug = self._qemu_capture_kasan(qemu, th_index)
        except Exception as e:
            self.err_msg("Exception occur when reporducing crash: {}".format(e))
            if qemu.instance.poll() == None:
                qemu.instance.kill()
            res = []
            trigger_hunted_bug = False
        return [res, trigger_hunted_bug, qemu.qemu_fail]

    def set_history_status(self):
        for name in self.results:
            if self.results[name]['trigger']:
                self.set_stage_text("Triggered")
                return
        self.set_stage_text("Failed")

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
                regx_match(message_drop_regx, line) or \
                (self._crash_start(line) and record_flag):
                    crash_flag = 1
                if record_flag:
                    crash.append(line)
                if (regx_match(boundary_regx, line) and record_flag) or \
                        regx_match(panic_regx, line) or \
                        (self._crash_start(line) and record_flag):
                    if crash_flag == 1:
                        res.append(crash)
                        crash = []
                        trigger_hunted_bug = True
                        qemu.kill_qemu = True
                    record_flag = 0
                    crash_flag = 0
                    continue
                if regx_match(boundary_regx, line):
                    record_flag ^= 1
                    crash_flag = 0
            out_begin = out_end
        return res, trigger_hunted_bug

    def _kernel_config_pre_check(self, qemu, config):
        out = qemu.command(cmds="grep {} /boot/config-`uname -r`".format(config), user=self.root_user, wait=True)
        for line in out:
            line = line.strip()
            if line == config:
                self.info_msg("{} is enabled".format(config))
                return True
        return False

    def _run_poc(self, qemu, work_dir, root, poc_feature):
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
    
    def _init_results(self):
        for distro in self.cfg.get_distros():
            distro_result = {}

            distro_result['missing_module'] = []
            distro_result['skip_funcs'] = []
            distro_result['device_tuning'] = []
            distro_result['interface_tuning'] = []
            distro_result['namespace'] = False
            distro_result['root'] = None
            distro_result['minimized'] = False
            distro_result['hash'] = self.case['hash']
            distro_result['trigger'] = False
            self.results[distro.distro_name] = distro_result

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
    
    def _write_to(self, content, name):
        file_path = "{}/{}".format(self.path_case_plugin, name)
        super()._write_to(content, file_path)

    def cleanup(self):
        super().cleanup()