from audioop import reverse
import queue, multiprocessing
import re, os, time, shutil, threading
from unittest import result

from plugins import AnalysisModule
from modules.vm import VMInstance
from infra.tool_box import *
from infra.strings import *
from infra.config.vendor import Vendor
from subprocess import Popen, STDOUT, PIPE, call
from plugins.modules_analysis import ModulesAnalysis
from syzmorph.plugins.syz_feature_minimize.syz_feature_minimize import SyzFeatureMinimize
from .error import *

qemu_output_window = 15
class BugReproduce(AnalysisModule):
    NAME = "BugReproduce"
    REPORT_START = "======================BugReproduce Report======================"
    REPORT_END =   "==================================================================="
    REPORT_NAME = "Report_BugReproduce"
    DEPENDENCY_PLUGINS = ["ModulesAnalysis", "CapabilityCheck", "SyzFeatureMinimize"]

    FEATURE_LOOP_DEVICE = 1 << 0
    FEATURE_MOD4ENV = 1 << 1
    FEATURE_NAMESPACE = 1 << 2

    def __init__(self):
        super().__init__()
        self.c_prog = False
        self.ori_c_prog = False
        self.syz_feature = {}
        self.syz_feature_mini = None
        self.bug_title = ''
        self.results = {}
        self.root_user = None
        self.normal_user = None
        self.distro_lock = threading.Lock()
        self.repro_timeout = None
        self._skip_regular_reproduce = False
        self._addition_modules = []
        
    def prepare(self):
        self._init_results()
        plugin = self.cfg.get_plugin(self.NAME)
        if plugin == None:
            self.err_msg("No such plugin {}".format(self.NAME))
        try:
            self.repro_timeout = int(plugin.timeout)
        except AttributeError:
            self.err_msg("Failed to get timeout")
            return False

        try:
            self._skip_regular_reproduce = plugin.skip_regular_reproduce
        except AttributeError:
            pass
        return self.prepare_on_demand()
    
    def prepare_on_demand(self):
        self._prepared = True
        return True
    
    def expt_handler(func):
        def inner(self, *args):
            try:
                ret = func(self, *args)
            except KASANDoesNotEnabled as e:
                raise e
            except ModprobePaniced as e:
                return [[], False, False, e.mod, e]
            except Exception as e:
                raise e
            return ret
        return inner
    
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

        if not self.plugin_finished("SyzFeatureMinimize"):
            self.info_msg("BugReproduce will use C Prog instead")
            self.ori_c_prog = True
            self.c_prog = True
        else:
            self.syz_feature_mini = self.cfg.get_plugin(SyzFeatureMinimize.NAME).instance
            self.syz_feature_mini.path_case_plugin = os.path.join(self.path_case, SyzFeatureMinimize.NAME)
            self.syz_feature = self.syz_feature_mini.results.copy()
            self.logger.info("Receive syz_feature: {} {}".format(self.syz_feature, self.syz_feature_mini))
            if self.syz_feature['prog_status'] == SyzFeatureMinimize.C_PROG:
                self.c_prog = False
            self.syz_feature.pop('prog_status')
        for distro in self.cfg.get_distros():
            self.info_msg("Reproducing bugs on {}".format(distro.distro_name))
            if self.syz_feature_mini != None:
                for each in self.syz_feature:
                    if not self.syz_feature[each]:
                        self.results[distro.distro_name]['skip_funcs'].append(each)
            x = threading.Thread(target=self.reproduce_async, args=(distro, output ), name="{} reproduce_async-{}".format(self.case_hash, distro.distro_name))
            x.start()
            time.sleep(1)
            if self.debug:
                x.join()

        for distro in self.cfg.get_distros():
            [distro_name, m] = output.get(block=True)
            self.logger.info("Receive result from {}: {}".format(distro_name, m))
            res[distro_name] = m
        
        return res
    
    def reproduce_async(self, distro, q):
        res = {}
        res["distro_name"] = distro.distro_name
        res["triggered"] = False
        res["bug_title"] = ""
        res["root"] = True
        
        if not self._skip_regular_reproduce:
            success, _ = self.reproduce(distro, func=self.capture_kasan, timeout=self.repro_timeout * 2+100, root=True)
            if success:
                res["triggered"] = True
                res["bug_title"] = self.bug_title
                res["root"] = True
                success, _ = self.reproduce(distro, func=self.capture_kasan, timeout=self.repro_timeout * 2+100, root=False)
                if success:
                    res["triggered"] = True
                    res["bug_title"] = self.bug_title
                    res["root"] = False
                self.results[distro.distro_name]['root'] = res['root']
                self.results[distro.distro_name]['trigger'] = True
                q.put([distro.distro_name, res])
                return
        
        if not self.plugin_finished("ModulesAnalysis"):
            self.info_msg("BugReproduce will not locate missing modules due to incorrectly results from ModulesAnslysis")
            q.put([distro.distro_name, res])
            return
        self.info_msg("{} does not trigger any bugs, try to enable missing modules".format(distro.distro_name))
        m = self.get_missing_modules(distro.distro_name)
        missing_modules = [e['name'] for e in m if e['type'] != 0 ]
        success, t = self.reproduce(distro, func=self.tweak_modules, func_args=(missing_modules, [], [],), attempt=1, root=True, log_prefix='missing-modules', timeout=len(missing_modules) * 2 * self.repro_timeout + 300)
        if success:
            self.results[distro.distro_name]['trigger'] = True
            tested_modules = t[0]
            res["triggered"] = True
            res["bug_title"] = self.bug_title
            res["root"] = True
            if tested_modules == []:
                self.err_msg("Tested modules are empty but trigger the bug. Please check if no modules are indeed required, or something wrong with the tested modules")
                q.put([distro.distro_name, res])
                return
            essential_modules = self.minimize_modules(distro, tested_modules, [tested_modules[::-1][0]])
            if essential_modules == None:
                self.err_msg("{} trigger the bug, but essential modules are not stable, fail to minimize".format(distro.distro_name))
                self.report.append("{} trigger the bug, but essential modules are not stable, fail to minimize".format(distro.distro_name))
                self.report.append("{} requires loading [{}] to trigger the bug".format(distro.distro_name, ",".join(tested_modules)))
                self.results[distro.distro_name]['missing_module'] = tested_modules
                self.results[distro.distro_name]['minimized'] = False
                self.results[distro.distro_name]['root'] = res['root']
            else:
                if self.check_module_priviledge(essential_modules):
                    success, _ = self.reproduce(distro, func=self.tweak_modules, func_args=(essential_modules, [], [],), attempt=1, root=False, log_prefix='verify_module_loading', timeout=2 * self.repro_timeout + 300)
                    if success:
                        res["root"] = False
                        self.results[distro.distro_name]['unprivileged_module_loading'] = True
                self.report.append("{} requires loading [{}] to trigger the bug".format(distro.distro_name, ",".join(essential_modules)))
                self.results[distro.distro_name]['missing_module'] = essential_modules
                self.results[distro.distro_name]['minimized'] = True
                self.results[distro.distro_name]['root'] = res['root']

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
    
    def minimize_modules(self, distro, missing_modules: list, essential_modules: list, root=True):
        missing_modules = missing_modules[::-1][1:]
        self.info_msg("{} is minimizing modules list {}, current essential list {}".format(distro.distro_name, missing_modules, essential_modules))
        success, t = self.reproduce(distro, func=self.tweak_modules, func_args=(missing_modules, essential_modules, []), root=True, attempt=1, log_prefix='minimize', timeout=len(missing_modules) * self.repro_timeout * 2 + 300)
        if success:
            missing_modules = t[0]
            if missing_modules != []:
                essential_modules.extend(t[::-1][0])
                return self.minimize_modules(distro, missing_modules, essential_modules)
            else:
                return essential_modules
        return None

    def reproduce(self, distro: Vendor, root: bool, func, func_args=(), log_prefix= "qemu", attempt=3, **kwargs):
        if root:
            self.set_stage_text("\[root] Booting {}".format(distro.distro_name))
        else:
            self.set_stage_text("\[user] Booting {}".format(distro.distro_name))
        if root:
            log_name = "{}-{}-root".format(log_prefix, distro.distro_name)
        else:
            log_name = "{}-{}-normal".format(log_prefix, distro.distro_name)
        result_queue = multiprocessing.Queue()
        func_args += (distro.distro_name, result_queue)
        distro.repro.init_logger(self.logger)
        self.root_user = distro.repro.root_user
        self.normal_user = distro.repro.normal_user
        
        c_prog = self.c_prog
        func_args += (c_prog, )
        while True:
            report, triggered, t = distro.repro.reproduce(func=func, func_args=func_args, root=root, work_dir=self.path_case_plugin, vm_tag=distro.distro_name, attempt=attempt, c_hash=self.case_hash, log_name=log_name, **kwargs)
            if not result_queue.empty():
                new_results = result_queue.get()
                self.results[distro.distro_name] = new_results[distro.distro_name]
            if triggered:
                title = self._BugChecker(report)
                self.bug_title = title
                return triggered, t
            if len(t) == 2: # only if expt is the type of ModeprobePaniced, we proceed
                panic_mod = t[0]
                expt = t[1]
                if isinstance(expt, ModprobePaniced):
                    missing_modules = func_args[0]
                    essential_modules = func_args[1]
                    preload_modules = func_args[2]
                    idx = missing_modules.index(panic_mod)
                    if idx == len(missing_modules) - 1:
                        break
                    preload_modules.extend(missing_modules[:idx])
                    missing_modules = missing_modules[idx:]
                    func_args = (missing_modules, essential_modules, preload_modules)
                    func_args += (distro.distro_name, result_queue, c_prog)
                    continue
            if not c_prog:
                c_prog = True
                l = list(func_args)
                l[-1] = c_prog
                func_args = tuple(l)
                continue
            break
        return False, t
    
    def rename_poc(self, root: bool):
        if root:
            shutil.move(os.path.join(self.path_case_plugin, "poc.c"), os.path.join(self.path_case_plugin, "poc_root.c"))
        else:
            shutil.move(os.path.join(self.path_case_plugin, "poc.c"), os.path.join(self.path_case_plugin, "poc_normal.c"))

    def get_missing_modules(self, distro_name):
        res = []
        module_analysis = self.cfg.get_plugin(ModulesAnalysis.NAME)
        r = module_analysis.instance.results
        if r == None:
            self.err_msg("ModulesAnalysis didn't finish")
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
                self.err_msg("{} doesn't have missing section".format(r[e]))
                raise(Exception("[{}] {} doesn't have missing section".format(self.case_hash, r[e])))

        def module_sort(e):
            return (e['type'], e['hook'] == False) 
        
        try: 
            res.sort(key=module_sort, reverse=True)
        except:
            self.err_msg("Failed to sort missing modules {}".format(res))
            raise Exception("[{}] failed to sort missing modules {}".format(self.case_hash, res))
        return res

    def tune_poc(self, root: bool, distro_name: str, src, dst, need_namespace=False):
        feature = 0
        # why don't we just enable namespace all the time?

        skip_funcs = ["setup_usb();", "setup_leak();"]
        data = []

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
        loop_func = r"^(static )?void loop\(.*\)"

        for i in range(0, len(code)):
            line = code[i].strip()
            if insert_line != []:
                for t in insert_line:
                    if i == t[0]:
                        data.append(t[1])
                        insert_line.remove(t)
            data.append(code[i])
            if regx_match(main_func, line):
                if need_namespace:
                    data.insert(len(data)-1, "#include \"sandbox.h\"\n")
                    insert_line.append([i+2, "setup_sandbox();\n"])
            
            """if regx_match(loop_func, line):
                if code[i+1].strip() == "{":
                    insert_line.append([i+2, "printf(\"MAGIC!!?REACH POC CORE FUNCTION\\n\");\n"])
            """
            for each in skip_funcs:
                if regx_match(each, line):
                    data.pop()
                    if each not in self.results[distro_name]['skip_funcs']:
                        self.results[distro_name]['skip_funcs'].append(each)

            # We dont have too much devices to connect, limit the number to 1
            if '*hash = \'0\' + (char)(a1 % 10);' in line:
                data.pop()
                data.append('*hash = \'0\' + (char)(a1 % 2);\n')

            if 'setup_loop_device' in line:
                if not (feature & self.FEATURE_LOOP_DEVICE):
                    feature |= self.FEATURE_LOOP_DEVICE
                    if 'loop_dev' not in self.results[distro_name]['device_tuning']:
                        self.results[distro_name]['device_tuning'].append('loop_dev')
            
            if 'hwsim80211_create_device' in line:
                if not (feature & self.FEATURE_MOD4ENV):
                    feature |= self.FEATURE_MOD4ENV
                    self.results[distro_name]['env_modules'].append('mac80211_hwsim')
                if 'mac80211_hwsim' not in self._addition_modules:
                    self._addition_modules.append('mac80211_hwsim')
                    self.results[distro_name]['unprivileged_module_loading'] = True

        if data != []:
            fdst.writelines(data)
            fdst.close()
            if need_namespace:
                src = os.path.join(self.path_package, "plugins/bug_reproduce/sandbox.h")
                dst = os.path.join(self.path_case_plugin, "sandbox.h")
                shutil.copyfile(src, dst)
        else:
            self.err_msg("Cannot find real PoC function")
        return feature
    
    def check_poc_capability(self):
        regx = r'([A-Z_]+) seems to be bypassable'
        cap_report = os.path.join(self.path_case, "CapabilityCheck", "Report_CapabilityCheck")
        if not self.plugin_finished("CapabilityCheck"):
            return True
        if not os.path.exists(cap_report):
            return False
        with open(cap_report, "r") as f:
            data = f.readlines()
            for line in data:
                if regx_match(regx, line):
                    return True
        return False
    
    def success(self):
        for key in self.results:
            if self.results[key]['trigger']:
                return True
        return False
    
    def generate_report(self):
        final_report = "\n".join(self.report)
        self.info_msg(final_report)
        self._write_to(final_report, self.REPORT_NAME)

    def warp_qemu_capture_kasan(self, qemu, th_index, q):
            try:
                res, trigger_hunted_bug = self._qemu_capture_kasan(qemu, th_index)
            except Exception as e:
                self.err_msg("Exception occur when reporducing crash: {}".format(e))
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

    @expt_handler
    def tweak_modules(self, qemu: VMInstance, root, missing_modules: list, essential_modules: list, preload_modules: list, distro_name: str, result_queue: queue.Queue, c_prog: bool):
        #threading.Thread(target=self._update_qemu_timer_status, args=(th_index, qemu), name="update_qemu_timer_status").start()
        
        tested_modules = []
        vm_tag = "-".join(qemu.tag.split('-')[:-1])

        qemu.logger.info("Missing modules: {}".format(missing_modules))
        qemu.logger.info("Loading preload modules: {}".format(preload_modules))
        self._enable_missing_modules(qemu, preload_modules)
        qemu.logger.info("Loading essential modules {}".format(essential_modules))
        if essential_modules != []:
            self._enable_missing_modules(qemu, essential_modules)
            trigger = self._execute(root, qemu, distro_name, c_prog)
            if trigger:
                self.results[vm_tag]["repeat"] = False
                result_queue.put(self.results)
                return tested_modules
            trigger = self._execute(root, qemu, distro_name, c_prog, namespace=True)
            if trigger:
                self.results[vm_tag]["repeat"] = False
                self.results[vm_tag]["namespace"] = True
                result_queue.put(self.results)
                return tested_modules
            trigger = self._execute(root, qemu, distro_name, c_prog, repeat=True)
            if trigger:
                self.results[vm_tag]["repeat"] = True
                result_queue.put(self.results)
                return tested_modules
            trigger = self._execute(root, qemu, distro_name, c_prog, repeat=True, namespace=True)
            if trigger:
                self.results[vm_tag]["repeat"] = True
                self.results[vm_tag]["namespace"] = True
                result_queue.put(self.results)
                return tested_modules
        
        for module in missing_modules:
            self.set_stage_text("testing {} on {}".format(module, qemu.tag))
            qemu.logger.info("****************************************")
            qemu.logger.info("Loading missing module {}".format(module))
            qemu.logger.info("****************************************")
            if not self._enable_missing_modules(qemu, [module]):
                continue
            tested_modules.append(module)
            trigger = self._execute(root, qemu, distro_name, c_prog)
            if trigger:
                self.results[vm_tag]["repeat"] = False
                result_queue.put(self.results)
                return tested_modules
            trigger = self._execute(root, qemu, distro_name, c_prog, namespace=True)
            if trigger:
                self.results[vm_tag]["repeat"] = False
                self.results[vm_tag]["namespace"] = True
                result_queue.put(self.results)
                return tested_modules
            trigger = self._execute(root, qemu, distro_name, c_prog, repeat=True)
            if trigger:
                self.results[vm_tag]["repeat"] = True
                result_queue.put(self.results)
                return tested_modules
            trigger = self._execute(root, qemu, distro_name, c_prog, repeat=True, namespace=True)
            if trigger:
                self.results[vm_tag]["repeat"] = True
                self.results[vm_tag]["namespace"] = True
                result_queue.put(self.results)
                return tested_modules
        result_queue.put(self.results)
        return []
    
    @expt_handler
    def capture_kasan(self, qemu, root, distro_name: str, result_queue: queue.Queue, c_prog: bool):
        #threading.Thread(target=self._update_qemu_timer_status, args=(th_index, qemu), name="update_qemu_timer_status").start()
        vm_tag = "-".join(qemu.tag.split('-')[:-1])

        if len(self._addition_modules) > 0:
            self.logger.info("Loading addition modules for environment setup: {}".format(self._addition_modules))
            self._enable_missing_modules(qemu, self._addition_modules)

        trigger = self._execute(root, qemu, distro_name, c_prog)
        if trigger:
            self.results[vm_tag]["repeat"] = False
            result_queue.put(self.results)
            return
        trigger = self._execute(root, qemu, distro_name, c_prog, namespace=True)
        if trigger:
            self.results[vm_tag]["repeat"] = False
            self.results[distro_name]['namespace'] = True
            result_queue.put(self.results)
            return
        trigger = self._execute(root, qemu, distro_name, c_prog, repeat=True)
        if trigger:
            self.results[vm_tag]["repeat"] = True
            result_queue.put(self.results)
        trigger = self._execute(root, qemu, distro_name, c_prog, repeat=True, namespace=True)
        if trigger:
            self.results[vm_tag]["repeat"] = True
            self.results[distro_name]['namespace'] = True
            result_queue.put(self.results)
        return

    def set_history_status(self):
        for name in self.results:
            if self.results[name]['trigger']:
                self.set_stage_text("Triggered")
                return
        self.set_stage_text("Failed")

    def _update_qemu_timer_status(self, index, qemu):
        while True:
            if qemu.instance.poll() != None:
                break
            self.set_stage_status("[{}/3] {}/{}".format(index, qemu.timer, qemu.timeout))
            time.sleep(5)
    
    def _check_poc_existence(self, qemu, user):
        out = qemu.command(cmds="ls poc", user=user, wait=True)
        for line in out:
            if "No such file or directory" in line:
                return False
        return True

    def _execute(self, root, qemu, distro_name, c_prog, repeat=False, namespace=False):
        self.distro_lock.acquire()
        if self.ori_c_prog:
            src = os.path.join(self.path_case, "poc.c")
            if not root:
                dst = os.path.join(self.path_case_plugin, "poc_normal.c")
                poc_name = "poc_normal.c"
            else:
                dst = os.path.join(self.path_case_plugin, "poc_root.c")
                poc_name = "poc_root.c"
        else:
            if repeat:
                src = os.path.join(self.path_case, "PoC_repeat.c")
            else:
                src = os.path.join(self.path_case, "PoC_no_repeat.c")
            if not root:
                if repeat:
                    poc_name = "poc_normal_repeat.c"
                else:
                    poc_name = "poc_normal_no_repeat.c"
            else:
                if repeat:
                    poc_name = "poc_root_repeat.c"
                else:
                    poc_name = "poc_root_no_repeat.c"
            dst = os.path.join(self.path_case_plugin, poc_name)
        poc_feature = self.tune_poc(root, distro_name, src, dst, namespace)
        self.distro_lock.release()
        
        if c_prog:
            return self._execute_poc(root, qemu, poc_feature, poc_name, repeat)
        else:
            return self._execute_syz(root, qemu, poc_feature, repeat, namespace)
    
    def _execute_syz(self, root, qemu: VMInstance, poc_feature, repeat=False, namespace=False):
        if root:
            user = self.root_user
        else:
            user = self.normal_user
        syz_feature_mini_path = os.path.join(self.path_case, "SyzFeatureMinimize")
        i386 = False
        if '386' in self.case['manager']:
            i386 = True
        syz_execprog = os.path.join(syz_feature_mini_path, "syz-execprog")
        syz_executor = os.path.join(syz_feature_mini_path, "syz-executor")
        testcase = os.path.join(self.path_case, "testcase")
        qemu.upload(user=user, src=[testcase], dst="~/", wait=True)
        qemu.upload(user=user, src=[syz_execprog, syz_executor], dst="/tmp", wait=True)
        qemu.command(cmds="chmod +x /tmp/syz-execprog /tmp/syz-executor", user=user, wait=True)
        qemu.logger.info("running PoC")
        qemu.command(cmds="echo \"6\" > /proc/sys/kernel/printk", user=self.root_user, wait=True)
        self._check_poc_feature(poc_feature, qemu, user)
        testcase_text = open(testcase, "r").readlines()

        if namespace:
            cmds = self.syz_feature_mini.make_syz_command(testcase_text, self.syz_feature, i386, repeat=repeat, sandbox="namespace", root=root)
        else:
            cmds = self.syz_feature_mini.make_syz_command(testcase_text, self.syz_feature, i386, repeat=repeat, root=root)
        qemu.command(cmds=cmds, user=user, wait=True, timeout=self.repro_timeout)
        qemu.command(cmds="killall syz-executor && killall syz-execprog", user="root", wait=True)

        time.sleep(5)
        return qemu.trigger_crash

    def _execute_poc(self, root, qemu: VMInstance, poc_feature, poc_src, repeat=False):
        if root:
            user = self.root_user
        else:
            user = self.normal_user
        poc_path = os.path.join(self.path_case_plugin, poc_src)
        qemu.upload(user=user, src=[poc_path], dst="~/", wait=True)
        if os.path.exists(os.path.join(self.path_case_plugin, "sandbox.h")):
            sandbox_src = os.path.join(self.path_case_plugin, "sandbox.h")
            qemu.upload(user=user, src=[sandbox_src], dst="~/", wait=True)
        if '386' in self.case['manager']:
            qemu.command(cmds="gcc -m32 -pthread -o poc {}".format(poc_src), user=user, wait=True)
        else:
            qemu.command(cmds="gcc -pthread -o poc {}".format(poc_src), user=user, wait=True)
        if not self._check_poc_existence(qemu, user):
            self.logger.fatal("Fail to compile poc!")
            return [[], False]

        if repeat and self.ori_c_prog:
            script = os.path.join(self.path_package, "scripts/run-script.sh")
            chmodX(script)
            p = Popen([script, str(qemu.port), self.path_case_plugin, qemu.key, user],
                stderr=STDOUT,
                stdout=PIPE)
            with p.stdout:
                log_anything(p.stdout, qemu.logger, self.debug)
            # It looks like scp returned without waiting for all file finishing uploading.
            # Sleeping for 1 second to ensure everything is ready in vm
            time.sleep(1)
        
        qemu.logger.info("running PoC")
        qemu.command(cmds="echo \"6\" > /proc/sys/kernel/printk", user=self.root_user, wait=True)
        self._check_poc_feature(poc_feature, qemu, user)
        if repeat and self.ori_c_prog:
            qemu.command(cmds="chmod +x run.sh && ./run.sh", user=user, wait=True, timeout=self.repro_timeout)
        else:
            qemu.command(cmds="rm -rf ./tmp", user=user, wait=True)
            qemu.command(cmds="mkdir ./tmp && mv ./poc ./tmp && cd ./tmp && chmod +x poc && ./poc", user=user, wait=True, timeout=self.repro_timeout)
        qemu.logger.info("Killing PoC")
        qemu.command(cmds="killall poc", user=self.root_user, wait=True)
        self.set_stage_text("gathering output")
        time.sleep(5)
        return qemu.trigger_crash

    def _enable_missing_modules(self, qemu, manual_enable_modules):
        for each in manual_enable_modules:
            args = self._module_args(each)
            out = qemu.command(cmds="modprobe {}{}".format(each, args), user=self.root_user, wait=True, timeout=60)
            if len(out) > 1:
                if 'modprobe: FATAL: Module {} not found in directory'.format(each) in out[1]:
                    raise ModprobePaniced(each)
                if 'Exec format error' in out[1]:
                    raise ModprobePaniced(each)
            out = qemu.command(cmds="lsmod | grep {}".format(each), user=self.root_user, wait=True)
            if len(out) == 1:
                raise ModprobePaniced(each)
        return True
    
    def _module_args(self, module):
        # This is not perfect, nf_conntrack has arguments recently
        # and we don't know what other modules have arguments and what to do with those arguments
        # Not sure how big of a problem this is
        if module == "nf_conntrack":
            return " enable_hooks=1"
        return ""

    def _check_poc_feature(self, poc_feature, qemu, user):
        script_name = "check-poc-feature.sh"
        script = os.path.join(self.path_package, "plugins/bug_reproduce", script_name)
        shutil.copy(script, self.path_case_plugin)
        cur_script = os.path.join(self.path_case_plugin, script_name)
        qemu.upload(user=user, src=[cur_script], dst="~/", wait=True)
        qemu.command(cmds="chmod +x check-poc-feature.sh && ./check-poc-feature.sh {}".format(poc_feature), user=user, wait=True)

    def _kernel_config_pre_check(self, qemu, config):
        out = qemu.command(cmds="grep {} /boot/config-`uname -r`".format(config), user=self.root_user, wait=True)
        for line in out:
            line = line.strip()
            if line == config:
                self.info_msg("{} is enabled".format(config))
                return True
        if out == None:
            self.err_msg("kernel config check failed due to ssh problem")
        return False
    
    def _init_results(self):
        for distro in self.cfg.get_distros():
            distro_result = {}

            distro_result['missing_module'] = []
            distro_result['skip_funcs'] = []
            distro_result['device_tuning'] = []
            distro_result['env_modules'] = []
            distro_result['interface_tuning'] = []
            distro_result['namespace'] = False
            distro_result['root'] = None
            distro_result['minimized'] = False
            distro_result['repeat'] = False
            distro_result['hash'] = self.case['hash']
            distro_result['trigger'] = False
            distro_result['unprivileged_module_loading'] = False
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
                            self._write_to(title, "VendorDoubleFree")
                            flag_double_free = True
                            break
                    if regx_match(kasan_write_addr_regx, line) and not flag_kasan_write:
                            self.info_msg("KASAN MemWrite")
                            self._write_to(title, "VendorMemWrite")
                            flag_kasan_write = True
                            break
                    if regx_match(kasan_read_addr_regx, line) and not flag_kasan_read:
                            self.info_msg("KASAN MemRead")
                            self._write_to(title, "VendorMemRead")
                            flag_kasan_read = True
                            break
        return title

    def _write_to(self, content, name):
        file_path = "{}/{}".format(self.path_case_plugin, name)
        super()._write_to(content, file_path)
    
    def cleanup(self):
        super().cleanup()

