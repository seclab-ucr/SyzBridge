import re, os, time, shutil

from plugins import AnalysisModule
from modules.vm import VMInstance
from infra.tool_box import *
from infra.strings import *
from subprocess import Popen, STDOUT, PIPE, call

class BugReproduce(AnalysisModule):
    NAME = "BugReproduce"
    REPORT_START = "======================BugReproduce Report======================"
    REPORT_END =   "==================================================================="
    REPORT_NAME = "Report_BugReproduce"

    def __init__(self):
        super().__init__()
        self.report = ''
        self.path_case_plugin = None
        self.bug_title = ''
        
    def prepare(self):
        if not self.manager.has_c_repro:
            self.logger.info("Case does not have c reproducer")
            return False
        return self.prepare_on_demand()
    
    def prepare_on_demand(self):
        self._prepared = True
        self.logger = self._get_child_logger(self.case_logger)
        return True
    
    def check(func):
        def inner(self):
            ret = func(self)
            if ret != None:
                title = ret[0]
                non_root = ret[1]
                if non_root:
                    str_privilege = " by normal user"
                else:
                    str_privilege = " by root user"
                self.main_logger.info("Trigger a Kasan bug: {} {}".format(title, str_privilege))
                self._move_to_success = True
            else:
                self.main_logger.info("Fail to trigger the bug")
            return ret
        return inner

    @check
    def run(self):
        self.logger.info("start reproducing bugs on {}".format(self.cfg.vendor_name))
        self.repro.setup(getattr(VMInstance, self.cfg.vendor_name.upper()))
        if self.reproduce(root=False):
            return [self.bug_title, True]
        if self.reproduce(root=True):
            return [self.bug_title, False]
        return None

    def reproduce(self, root: bool):
        self.tune_poc(root)
        if root:
            log_name = "qemu-{}-root".format(self.cfg.vendor_name)
        else:
            log_name = "qemu-{}-normal".format(self.cfg.vendor_name)
        report, triggered = self.repro.reproduce(self.case_hash, self.path_case_plugin, self.capture_kasan, root, log_name)
        self.rename_poc(root)
        if triggered:
            is_kasan_bug, title = self._KasanChecker(report)
            if is_kasan_bug:
                self.bug_title = title
                return True
        return False
    
    def rename_poc(self, root: bool):
        if root:
            shutil.move(os.path.join(self.path_case_plugin, "poc.c"), os.path.join(self.path_case_plugin, "poc_root.c"))
        else:
            shutil.move(os.path.join(self.path_case_plugin, "poc.c"), os.path.join(self.path_case_plugin, "poc_normal.c"))

    def tune_poc(self, root: bool):
        sandbox_code = """
#include <sched.h>

void setup_sandbox() {
    int real_uid = getuid();
    int real_gid = getgid();

    if (unshare(CLONE_NEWUSER) != 0) {
        perror("[-] unshare(CLONE_NEWUSER)");
        exit(EXIT_FAILURE);
    }

    if (!write_file("/proc/self/setgroups", "deny")) {
        perror("[-] write_file(/proc/self/set_groups)");
        exit(EXIT_FAILURE);
    }
    if (!write_file("/proc/self/uid_map", "0 %d 1\\n", real_uid)){
        perror("[-] write_file(/proc/self/uid_map)");
        exit(EXIT_FAILURE);
    }
    if (!write_file("/proc/self/gid_map", "0 %d 1\\n", real_gid)) {
        perror("[-] write_file(/proc/self/gid_map)");
        exit(EXIT_FAILURE);
    }

    if (unshare(CLONE_NEWNS) != 0) {
        perror("unshare(CLONE_NEWNS)");
        exit(EXIT_FAILURE);
    }

    if (unshare(CLONE_NEWNET) != 0) {
        perror("[-] unshare(CLONE_NEWNET)");
        exit(EXIT_FAILURE);
    }
}"""
        if not root:
            data = []
            src = os.path.join(self.path_case, "poc.c")
            dst = os.path.join(self.path_case_plugin, "poc.c")
            poc_func = ""
            fsrc = open(src, "r")
            fdst = open(dst, "w")

            code = fsrc.readlines()
            fsrc.close()
            text = "".join(code)
            if text.find("int main") != -1:
                poc_func = r"^int main"
            for i in range(0, len(code)):
                line = code[i].strip()
                if regx_match(poc_func, line):
                    start_line = i
                    data = code[:start_line]
                    data.append(sandbox_code)
                    data.append("\n")
                    data.extend(code[start_line:start_line+2])
                    data.append("setup_sandbox();\n")
                    data.extend(code[start_line+2:])
                    break
            if data != []:
                fdst.writelines(data)
                fdst.close()
            else:
                self.logger.error("Cannot find real PoC function")
        self._compile_poc()
    
    def success(self):
        return self._move_to_success
    
    def generate_report(self):
        pass
    
    def capture_kasan(self, qemu, th_index, poc_path, queue, root):
        qemu_close = False
        out_begin = 0
        record_flag = 0
        kasan_flag = 0
        write_flag = 0
        double_free_flag = 0
        read_flag = 0
        crash = []
        res = []
        trgger_hunted_bug = False

        self._run_poc(qemu, poc_path, root)
        try:
            while not qemu_close:
                if qemu.instance.poll() != None:
                    qemu_close = True
                out_end = len(qemu.output)
                for line in qemu.output[out_begin:]:
                    if regx_match(call_trace_regx, line) or \
                    regx_match(message_drop_regx, line):
                        record_flag = 1
                    if regx_match(boundary_regx, line) or \
                    regx_match(panic_regx, line):
                        if record_flag == 1:
                            res.append(crash)
                            crash = []
                            if kasan_flag and (write_flag or read_flag or double_free_flag):
                                trgger_hunted_bug = True
                                if write_flag:
                                    self.logger.debug("QEMU threaded {}: OOB/UAF write triggered".format(th_index))
                                if double_free_flag:
                                    self.logger.debug("QEMU threaded {}: Double free triggered".format(th_index))
                                if read_flag:
                                    self.logger.debug("QEMU threaded {}: OOB/UAF read triggered".format(th_index)) 
                                qemu.kill_qemu = True                      
                                break
                        record_flag = 1
                        continue
                    if (regx_match(kasan_mem_regx, line) and 'null-ptr-deref' not in line):
                        kasan_flag = 1
                    if regx_match(write_regx, line):
                        write_flag = 1
                    if regx_match(kasan_double_free_regx, line):
                        double_free_flag = 1
                    if regx_match(read_regx, line):
                        read_flag = 1
                    if record_flag or kasan_flag:
                        crash.append(line)
                out_begin = out_end
        except Exception as e:
                self.logger.error("Exception occur when reporducing crash: {}".format(e))
                if qemu.instance.poll() == None:
                    qemu.instance.kill()
        queue.put([res, trgger_hunted_bug, qemu.qemu_fail], block=False)
    
    def _compile_poc(self):
        call(["gcc", "-pthread", "-static", "-o", "poc", "poc.c"], cwd=self.path_case_plugin)
    
    def _run_poc(self, qemu, poc_path, root):
        if root:
            user = "root"
        else:
            user = "etenal"
        qemu.upload(user=user, src=[poc_path], dst="~/", wait=True)
        self.logger.info("running PoC")
        script = "syzmorph/scripts/run-script.sh"
        chmodX(script)
        p = Popen([script, str(qemu.port), self.path_case_plugin, qemu.key, user],
            stderr=STDOUT,
            stdout=PIPE)
        with p.stdout:
            log_anything(p.stdout, self.logger, self.debug)
        # It looks like scp returned without waiting for all file finishing uploading.
        # Sleeping for 1 second to ensure everything is ready in vm
        time.sleep(1)
        qemu.command(cmds="chmod +x run.sh && ./run.sh", user=user, wait=False)
        return
    
    def _KasanChecker(self, report):
        title = None
        ret = False
        flag_double_free = False
        flag_kasan_write = False
        flag_kasan_read = False
        if report != []:
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
                            ret = True
                            self.logger.info("Double free")
                            self._write_to(self.case_hash, "LTSDoubleFree")
                            flag_double_free = True
                            break
                    if regx_match(kasan_write_addr_regx, line) and not flag_kasan_write:
                            ret = True
                            self.logger.info("KASAN MemWrite")
                            self._write_to(self.case_hash, "LTSMemWrite")
                            flag_kasan_write = True
                            break
                    if regx_match(kasan_read_addr_regx, line) and not flag_kasan_read:
                            ret = True
                            self.logger.info("KASAN MemRead")
                            self._write_to(self.case_hash, "LTSMemRead")
                            flag_kasan_read = True
                            break
        return ret, title
    
    def _get_child_logger(self, logger):
        child_logger = logger.getChild(self.NAME)
        child_logger.propagate = True
        child_logger.setLevel(logger.level)

        handler = logging.FileHandler("{}/log".format(self.path_case_plugin))
        format = logging.Formatter('%(message)s')
        handler.setFormatter(format)
        child_logger.addHandler(handler)
        return child_logger
    
    def _write_to(self, content, name):
        file_path = "{}/{}".format(self.path_case_plugin, name)
        super()._write_to(content, file_path)

