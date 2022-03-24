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

class BugReproduce(AnalysisModule):
    NAME = "BugReproduce"
    REPORT_START = "======================BugReproduce Report======================"
    REPORT_END =   "==================================================================="
    REPORT_NAME = "Report_BugReproduce"
    DEPENDENCY_PLUGINS = ["ModulesAnalysis"]

    FEATURE_LOOP_DEVICE = 1

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
            q.put([distro.distro_name, res])
            return
        
        self.logger.info("{} does not trigger any bugs, try to enable missing modules".format(distro.distro_name))
        m = self.get_missing_modules(distro.distro_name)
        missing_modules = [e['name'] for e in m ]
        success, t = self.reproduce(distro, func=self.tweak_modules, func_args=(missing_modules, [], ), root=True, log_prefix='missing-modules', timeout=MAX_BUG_REPRODUCE_TIMEOUT)
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
                self.logger.error("{} trigger the bug, but essential modules are not stable, fail to minimize".format(distro.distro_name))
            else:
                if self.check_module_priviledge(essential_modules):
                    res["root"] = False
                self.report.append("{} requires loading [{}] to trigger the bug".format(distro.distro_name, ",".join(essential_modules)))

        q.put([distro.distro_name, res])
        return
    
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
        self.logger.info("{} is minimizing modules list {}, current essential list {}".format(distro.distro_name, tested_modules, essential_modules))
        success, t = self.reproduce(distro, func=self.tweak_modules, func_args=(tested_modules, essential_modules), root=True, log_prefix='minimize', timeout=MAX_BUG_REPRODUCE_TIMEOUT)
        if success:
            tested_modules = t[0]
            if tested_modules != []:
                essential_modules.extend(t[::-1][0])
                return self.minimize_modules(distro, tested_modules, essential_modules)
            else:
                return essential_modules
        return None

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

    def get_missing_modules(self, distro_name):
        res = []
        t = os.path.join(self.path_case, ModulesAnalysis.NAME, "missing_modules.json")
        if not os.path.exists(t):
            return res
        r = json.load(open(t, "r"))
        res = []
        for e in r:
            try:
                if distro_name in r[e]['missing']:
                    t = r[e].copy()
                    for key in t['missing'][distro_name]:
                        t[key] = t['missing'][distro_name][key]
                    t.pop('missing')
                    res.append(t)
            except KeyError:
                self.logger.error("{} doesn't have missing section".format(r[e]))
                raise(Exception("[{}] {} doesn't have missing section".format(self.case_hash, r[e])))

        def module_sort(e):
            return (e['type'], e['hook'] == False) 
        
        try: 
            res.sort(key=module_sort, reverse=True)
        except:
            self.logger.error("Failed to sort missing modules {}".format(res))
            raise Exception("[{}] failed to sort missing modules {}".format(self.case_hash, res))
        return res

    def tune_poc(self, root: bool):
        feature = 0

        skip_funcs = [r"setup_usb\(\);", r"setup_leak\(\);", r"setup_cgroups\(\);", r"initialize_cgroups\(\);", r"setup_cgroups_loop\(\);"]
        data = []
        src = os.path.join(self.path_case, "poc.c")
        if not root:
            dst = os.path.join(self.path_case_plugin, "poc_normal.c")
        else:
            dst = os.path.join(self.path_case_plugin, "poc_root.c")

        if os.path.exists(dst):
            os.remove(dst)

        main_func = ""
        insert_line = []
        fsrc = open(src, "r")
        fdst = open(dst, "w")

        code = fsrc.readlines()
        fsrc.close()
        text = "".join(code)
        if text.find("int main") != -1:
            main_func = r"^int main"

        for i in range(0, len(code)):
            line = code[i].strip()
            if insert_line != []:
                for t in insert_line:
                    if i == t[0]:
                        data.append(t[1])
                        insert_line.remove(t)
            data.append(code[i])
            if not root:
                if regx_match(main_func, line):
                    data.insert(len(data)-1, "#include \"sandbox.h\"\n")
                    insert_line.append([i+2, "setup_sandbox();\n"])

            for each in skip_funcs:
                if regx_match(each, line):
                    data.pop()

            # We dont have too much devices to connect, limit the number to 1
            if '*hash = \'0\' + (char)(a1 % 10);' in line:
                data.pop()
                data.append('*hash = \'0\' + (char)(a1 % 2);')

            if 'setup_loop_device' in line:
                feature |= self.FEATURE_LOOP_DEVICE


        if data != []:
            fdst.writelines(data)
            fdst.close()
            if not root:
                src = os.path.join(self.path_package, "plugins/bug_reproduce/sandbox.h")
                dst = os.path.join(self.path_case_plugin, "sandbox.h")
                shutil.copyfile(src, dst)
        else:
            self.logger.error("Cannot find real PoC function")
        self._compile_poc(root)
        return feature
    
    def success(self):
        return self._move_to_success
    
    def generate_report(self):
        final_report = "\n".join(self.report)
        self.logger.info(final_report)
        self._write_to(final_report, self.REPORT_NAME)

    def tweak_modules(self, qemu, th_index, poc_path, root, missing_modules: list, essential_modules: list, poc_feature: int):
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
        
        qemu.logger.info("Loading essential modules {}".format(essential_modules))
        if essential_modules != []:
            self._enable_missing_modules(qemu, essential_modules)
            self._execute_poc(root, qemu, poc_path, poc_feature)
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
            qemu.logger.info("Loading missing module {}".format(module))
            self._enable_missing_modules(qemu, [module])
            tested_modules.append(module)
            self._execute_poc(root, qemu, poc_path, poc_feature)
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
    
    def _execute_poc(self, root, qemu, poc_path, poc_feature):
        if root:
            user = "root"
        else:
            user = "etenal"
        qemu.command(cmds="killall poc", user="root", wait=True)
        qemu.upload(user=user, src=[poc_path], dst="~/", wait=True)
        qemu.logger.info("running PoC")
        qemu.command(cmds="echo \"6\" > /proc/sys/kernel/printk", user="root", wait=True)
        self._check_poc_feature(poc_feature, qemu, user)
        qemu.command(cmds="rm -rf ./tmp && mkdir ./tmp && mv ./poc ./tmp && cd ./tmp && chmod +x poc && ./poc", user=user, wait=True, timeout=BUG_REPRODUCE_TIMEOUT)
                
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
                        if kasan_flag:
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
    
    def _check_poc_feature(self, poc_feature, qemu, user):
        script_name = "check-poc-feature.sh"
        script = os.path.join(self.path_package, "plugins/bug_reproduce", script_name)
        shutil.copy(script, self.path_case_plugin)
        cur_script = os.path.join(self.path_case_plugin, script_name)
        qemu.upload(user=user, src=[cur_script], dst="~/", wait=True)
        qemu.command(cmds="chmod +x check-poc-feature.sh && ./check-poc-feature.sh {}".format(poc_feature), user=user, wait=True)

    def _kernel_config_pre_check(self, qemu, config):
        out = qemu.command(cmds="grep {} /boot/config-`uname -r`".format(config), user="root", wait=True)
        for line in out:
            line = line.strip()
            if line == config:
                self.logger.info("{} is enabled".format(config))
                return True
        return False

    def _run_poc(self, qemu, poc_path, root, poc_feature):
        if root:
            user = "root"
        else:
            user = "etenal"
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
        qemu.command(cmds="echo \"6\" > /proc/sys/kernel/printk", user="root", wait=True)
        self._check_poc_feature(poc_feature, qemu, user)
        qemu.command(cmds="chmod +x run.sh && ./run.sh", user=user, wait=False)
        return
    
    def _BugChecker(self, report):
        title = None
        flag_double_free = False
        flag_kasan_write = False
        flag_kasan_read = False
        if report != []:
            title = report[0][0]
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

