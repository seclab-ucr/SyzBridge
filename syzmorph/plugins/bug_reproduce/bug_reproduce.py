from audioop import reverse
import queue
import re, os, time, shutil, threading

from plugins import AnalysisModule
from modules.vm import VMInstance
from infra.tool_box import *
from infra.strings import *
from subprocess import Popen, STDOUT, PIPE, call
from plugins.modules_analysis import ModulesAnalysis

class BugReproduce(AnalysisModule):
    NAME = "BugReproduce"
    REPORT_START = "======================BugReproduce Report======================"
    REPORT_END =   "==================================================================="
    REPORT_NAME = "Report_BugReproduce"
    DEPENDENCY_PLUGINS = ["ModulesAnalysis"]

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
            return

        self.logger.info("{} does not trigger any bug, try to enable moissing modules".format(distro.distro_name))
        m = self.get_missing_modules()
        missing_modules = [e['name'] for e in m ]
        success, t = self.reproduce(distro, func=self.tweak_modules, func_args=(missing_modules, [], ), root=True)
        if success:
            tested_modules = t[0]
            res["triggered"] = True
            res["bug_title"] = self.bug_title
            res["root"] = True
            if tested_modules == []:
                self.logger.error("Tested modules are empty but trigger the bug. Please check if no modules are indeed required, or something wrong with the tested modules")
                q.put([distro.distro_name, res])
                return
            essential_modules = self.minimize_modules(distro, tested_modules, [tested_modules[::-1][0]])
            if essential_modules == None:
                self.logger.error("Essential modules are not stable, fail to minimize")
            else:
                if self.check_module_priviledge(essential_modules):
                    res["root"] = False
                self.report.append("{} requires loading [{}] to trigger the bug".format(distro.distro_name, ",".join(essential_modules)))

        q.put([distro.distro_name, res])
    
    def check_module_priviledge(self, essential_modules):
        ret = True
        loadable = {}
        with open(os.path.join(self.path_package, "resources/loadable_modules"), "r") as f:
            text = f.readlines()
            for line in text:
                line = line.strip()
                if line == "" or line[0] == "#":
                    continue
                loadable[line] = True

        for e in essential_modules:
            if e not in loadable:
                ret = False
                self.report.append("{} is not in loadable list".format(e))
        return ret
    
    def minimize_modules(self, distro, tested_modules: list, essential_modules: list):
        tested_modules = tested_modules[::-1][1:]
        success, t = self.reproduce(distro, func=self.tweak_modules, func_args=(tested_modules, essential_modules), root=True)
        if success:
            tested_modules = t[0]
            if tested_modules != []:
                essential_modules.extend(t[::-1][0])
                return self.minimize_modules(distro, tested_modules, essential_modules)
            else:
                return essential_modules
        return None

    def reproduce(self, distro, root: bool, func, func_args=()):
        self.distro_lock.acquire()
        self.tune_poc(root)
        self.distro_lock.release()
        if root:
            log_name = "qemu-{}-root".format(distro.distro_name)
        else:
            log_name = "qemu-{}-normal".format(distro.distro_name)
        report, triggered, t = distro.repro.reproduce(func=func, func_args=func_args, root=root, work_dir=self.path_case_plugin, vm_tag=distro.distro_name, c_hash=self.case_hash, log_name=log_name)
        if triggered:
            is_kasan_bug, title = self._KasanChecker(report)
            if is_kasan_bug:
                self.bug_title = title
                return True, t
        return False, t
    
    def rename_poc(self, root: bool):
        if root:
            shutil.move(os.path.join(self.path_case_plugin, "poc.c"), os.path.join(self.path_case_plugin, "poc_root.c"))
        else:
            shutil.move(os.path.join(self.path_case_plugin, "poc.c"), os.path.join(self.path_case_plugin, "poc_normal.c"))

    def get_missing_modules(self):
        res = []
        t = os.path.join(self.path_case, ModulesAnalysis.NAME, "missing_modules.json")
        if not os.path.exists(t):
            return res
        r = json.load(open(t, "r"))
        res = [r[e] for e in r]

        def module_sort(e):
            return (e['type'], e['hook'] == False) 
        
        res.sort(key=module_sort, reverse=True)
        return res

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

    def tweak_modules(self, qemu, th_index, poc_path, root, missing_modules: list, essential_modules: list):
        tested_modules = []
        def warp_qemu_capture_kasan(qemu, th_index, q):
            try:
                res, trigger_hunted_bug = self._qemu_capture_kasan(qemu, th_index)
            except Exception as e:
                self.logger.error("Exception occur when reporducing crash: {}".format(e))
                if qemu.instance.poll() == None:
                    qemu.instance.kill()
                res = []
                trigger_hunted_bug = False
            # There might be a race condition in between _qemu_capture_kasan and tweak_modules
            # the queue 'q' put data after lock was released, tweak_modules has chance that assume
            # the queue is empty and no new output comes out of QEMU and thus have a wrong module
            # The race window is relatively small, I choose to ignore it to keep our function design
            # Will solve this problem if this race happens in real world
            q.put([res, trigger_hunted_bug])
        
        q = queue.Queue()
        threading.Thread(target=warp_qemu_capture_kasan, args=(qemu, th_index, q)).start()
        
        if essential_modules != []:
            self._enable_missing_modules(qemu, essential_modules)
            if root:
                user = "root"
            else:
                user = "etenal"
            qemu.upload(user=user, src=[poc_path], dst="~/", wait=True)
            self.logger.info("running PoC")
            qemu.command(cmds="echo \"6\" > /proc/sys/kernel/printk", user="root", wait=True)
            qemu.command(cmds="chmod +x poc && ./poc", user=user, wait=False, timeout=5*60)
            while True:
                try:
                    [res, trigger] = q.get(block=True, timeout=5)
                    if trigger:
                        qemu.alternative_func_output.put([res, trigger, qemu.qemu_fail, []], block=False)
                        return
                except queue.Empty:
                    if qemu.no_new_output():
                        break

        for module in missing_modules:
            self._enable_missing_modules(qemu, [module])
            tested_modules.append(module)
            if root:
                user = "root"
            else:
                user = "etenal"
            qemu.upload(user=user, src=[poc_path], dst="~/", wait=True)
            self.logger.info("running PoC")
            qemu.command(cmds="echo \"6\" > /proc/sys/kernel/printk", user="root", wait=True)
            qemu.command(cmds="chmod +x poc && ./poc", user=user, wait=False, timeout=5*60)
            while True:
                try:
                    [res, trigger] = q.get(block=True, timeout=5)
                    if trigger:
                        qemu.alternative_func_output.put([res, trigger, qemu.qemu_fail, tested_modules], block=False)
                        return
                except queue.Empty:
                    if qemu.no_new_output():
                        break
        qemu.alternative_func_output.put([[], False, False, []], block=False)
    
    def capture_kasan(self, qemu, th_index, poc_path, root):
        self._run_poc(qemu, poc_path, root)
        try:
            res, trigger_hunted_bug = self._qemu_capture_kasan(qemu, th_index)
        except Exception as e:
            self.logger.error("Exception occur when reporducing crash: {}".format(e))
            if qemu.instance.poll() == None:
                qemu.instance.kill()
            res = []
            trigger_hunted_bug = False
        qemu.alternative_func_output.put([res, trigger_hunted_bug, qemu.qemu_fail], block=False)

    def _qemu_capture_kasan(self, qemu, th_index):
        qemu_close = False
        out_begin = 0
        record_flag = 0
        kasan_flag = 0
        write_flag = 0
        double_free_flag = 0
        read_flag = 0
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
                    record_flag = 1
                if regx_match(boundary_regx, line) or \
                regx_match(panic_regx, line):
                    if record_flag == 1:
                        res.append(crash)
                        crash = []
                        if kasan_flag and (write_flag or read_flag or double_free_flag):
                            trigger_hunted_bug = True
                            if write_flag:
                                self.logger.debug("QEMU threaded {}: OOB/UAF write triggered".format(th_index))
                            if double_free_flag:
                                self.logger.debug("QEMU threaded {}: Double free triggered".format(th_index))
                            if read_flag:
                                self.logger.debug("QEMU threaded {}: OOB/UAF read triggered".format(th_index)) 
                            qemu.kill_qemu = True
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
        return res, trigger_hunted_bug

    def _enable_missing_modules(self, qemu, manual_enable_modules):
        for each in manual_enable_modules:
            qemu.command(cmds="modprobe {}".format(each), user="root", wait=True)
    
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
        qemu.command(cmds="echo \"6\" > /proc/sys/kernel/printk", user="root", wait=True)
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

