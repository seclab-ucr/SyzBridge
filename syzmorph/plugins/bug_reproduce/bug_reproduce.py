import queue
import re, os, time, shutil, threading

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
    DEPENDENCY_PLUGINS = []

    def __init__(self):
        super().__init__()
        self.report = []
        self.path_case_plugin = None
        self.bug_title = ''
        self.distro_lock = threading.Lock()
        
    def prepare(self):
        if not self.manager.has_c_repro:
            self.logger.info("Case does not have c reproducer")
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
                    self.main_logger.info("{} triggers a Kasan bug: {} {}".format(key ,title, str_privilege))
                    self.report.append("{} triggers a Kasan bug: {} {}".format(key ,title, str_privilege))
                    self._move_to_success = True
                else:
                    fail_name += key + " "
            if fail_name != "":
                self.main_logger.info("{} fail to trigger the bug".format(fail_name))
                self.report.append("{} fail to trigger the bug".format(fail_name))
            return ret
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
        if self.reproduce(distro, root=False):
            res["triggered"] = True
            res["bug_title"] = self.bug_title
            res["root"] = False
        elif self.reproduce(distro, root=True):
            res["triggered"] = True
            res["bug_title"] = self.bug_title
            res["root"] = True
        q.put([distro.distro_name, res])

    def reproduce(self, distro, root: bool):
        self.distro_lock.acquire()
        self.tune_poc(root)
        self.distro_lock.release()
        if root:
            log_name = "qemu-{}-root".format(distro.distro_name)
        else:
            log_name = "qemu-{}-normal".format(distro.distro_name)
        report, triggered = distro.repro.reproduce(func=self.capture_kasan, root=root, work_dir=self.path_case_plugin, vm_tag=distro.distro_name, c_hash=self.case_hash, log_name=log_name)
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
        if not root:
            data = []
            src = os.path.join(self.path_case, "poc.c")
            dst = os.path.join(self.path_case_plugin, "poc_normal.c")
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
                    data.append("#include \"sandbox.h\"")
                    data.append("\n")
                    data.extend(code[start_line:start_line+2])
                    data.append("setup_sandbox();\n")
                    data.extend(code[start_line+2:])
                    break
            if data != []:
                fdst.writelines(data)
                fdst.close()
                src = os.path.join(self.path_package, "plugins/bug_reproduce/sandbox.h")
                dst = os.path.join(self.path_case_plugin, "sandbox.h")
                shutil.copyfile(src, dst)
            else:
                self.logger.error("Cannot find real PoC function")
        else:
            src = os.path.join(self.path_case, "poc.c")
            dst = os.path.join(self.path_case_plugin, "poc_root.c")
            if os.path.exists(dst):
                os.remove(dst)
            shutil.copy(src, dst)
        self._compile_poc(root)
        return
    
    def success(self):
        return self._move_to_success
    
    def generate_report(self):
        final_report = "\n".join(self.report)
        self.logger.info(final_report)
        self._write_to(final_report, self.REPORT_NAME)
    
    def capture_kasan(self, qemu, th_index, poc_path, root):
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
        qemu.alternative_func_output.put([res, trgger_hunted_bug, qemu.qemu_fail], block=False)
    
    def _compile_poc(self, root: bool):
        if root:
            poc_file = "poc_root.c"
        else:
            poc_file = "poc_normal.c"
        call(["gcc", "-pthread", "-static", "-o", "poc", poc_file], cwd=self.path_case_plugin)
    
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
                            self._write_to(self.path_project, "VendorDoubleFree")
                            flag_double_free = True
                            break
                    if regx_match(kasan_write_addr_regx, line) and not flag_kasan_write:
                            ret = True
                            self.logger.info("KASAN MemWrite")
                            self._write_to(self.path_project, "VendorMemWrite")
                            flag_kasan_write = True
                            break
                    if regx_match(kasan_read_addr_regx, line) and not flag_kasan_read:
                            ret = True
                            self.logger.info("KASAN MemRead")
                            self._write_to(self.path_project, "VendorMemRead")
                            flag_kasan_read = True
                            break
        return ret, title
    
    def _write_to(self, content, name):
        file_path = "{}/{}".format(self.path_case_plugin, name)
        super()._write_to(content, file_path)

