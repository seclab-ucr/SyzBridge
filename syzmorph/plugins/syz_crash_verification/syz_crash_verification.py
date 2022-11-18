import os, logging
import shutil
import threading
import queue

from infra.tool_box import init_logger
from plugins import AnalysisModule
from modules.vm import VM
from infra.tool_box import *
from plugins import AnalysisModule
from plugins.syzkaller_interface import SyzkallerInterface


class SyzCrashVerification(AnalysisModule):
    NAME = "SyzCrashVerification"
    REPORT_START = "======================SyzCrashVerification Report======================"
    REPORT_END =   "==================================================================="
    REPORT_NAME = "Report_SyzCrashVerification"
    DEPENDENCY_PLUGINS = []
    SYZ_PROG = 0
    C_PROG = 1
    BOTH_FAIL = 2

    def __init__(self):
        super().__init__()
        self.i386 = False
        self.syz: SyzkallerInterface = None
        
    def prepare(self):
        plugin = self.cfg.get_plugin(self.NAME)
        if plugin == None:
            self.err_msg("No such plugin {}".format(self.NAME))
        try:
            self.repro_timeout = int(plugin.timeout)
            self.syzkaller_path = plugin.syzkaller_path
        except AttributeError:
            self.err_msg("Failed to get timeout")
            return False
        try:
            self.repro_attempt = int(plugin.attempt)
        except AttributeError:
            self.repro_attempt = 3
        return self.prepare_on_demand()
    
    def prepare_on_demand(self):
        self._prepared = True
        return True
    
    def success(self):
        return self._move_to_success
    
    def minimize_syz_feature(self):
        return self._minimize_syz_feature()
    
    def test_two_prog(self, features):
        if self._test_feature(None, features):
            return self.SYZ_PROG
        if self.test_PoC(features):
            return self.C_PROG
        return self.BOTH_FAIL
    
    def get_features(self, testcase_path):
        syz_repro = open(testcase_path, 'r').read()

        features = self._get_syz_features(syz_repro)
        return features

    def run(self):
        self.crash_main = os.path.join(self.syzkaller_path, 'workdir/crashes')
        syzbin_folder = 'linux_amd64'
        shutil.copyfile(os.path.join(self.syzkaller_path, 'bin/linux_amd64/syz-execprog'), os.path.join(self.path_case_plugin, 'syz-execprog'))
        shutil.copyfile(os.path.join(self.syzkaller_path, 'bin/{}/syz-executor'.format(syzbin_folder)), os.path.join(self.path_case_plugin, 'syz-executor'))
        shutil.copyfile(os.path.join(self.syzkaller_path, 'bin/syz-prog2c'), os.path.join(self.path_case_plugin, 'syz-prog2c'))
        for crash in os.listdir(self.crash_main):
            self.crash_path = os.path.join(self.crash_main, crash)
            testcase_path = os.path.join(self.crash_path, 'repro.prog')
            if not os.path.exists(testcase_path):
                self.main_logger.info("{} doesn't have testcase".format(crash))
                continue
            if os.path.exists(os.path.join(self.crash_path, 'repro.cprog')):
                continue
            if not self.test(testcase_path):
                self.main_logger.info("{} fail to extract c prog".format(crash))
            else:
                self.main_logger.info("{} trigger as non-root".format(crash))
    
    def test(self, testcase_path):
        features = self.minimize_syz_feature()
        if features == None:
            return False
        if not self.test_PoC(features, root=True):
            return False
        if self.test_PoC(features, root=False):
            self.generate_low_priv_file(testcase_path)
            shutil.copyfile(os.path.join(self.path_case_plugin, "poc_normal.c"), os.path.join(self.crash_path, "repro.cprog"))
            shutil.copyfile(os.path.join(self.path_case_plugin, "sandbox.h"), os.path.join(self.crash_path, "sandbox.h"))
        else:
            shutil.copyfile(os.path.join(self.path_case_plugin, "poc_root.c"), os.path.join(self.crash_path, "repro.cprog"))
            return False
        return True

    def test_PoC(self, features: list, repeat=False, root=True):
        if not self._test_feature(None, features, test_c_prog=True, repeat=repeat, root=root):
            return False
        return True
    
    def tune_poc(self, root: bool):
        feature = 0

        data = []
        src = os.path.join(self.path_case_plugin, "poc.c")
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
            if regx_match(main_func, line):
                data.insert(len(data)-1, "#include \"sandbox.h\"\n")
                insert_line.append([i+2, "setup_sandbox();\n"])

        if data != []:
            fdst.writelines(data)
            fdst.close()
            src = os.path.join(self.path_package, "plugins/syz_crash_verification/sandbox.h")
            dst = os.path.join(self.path_case_plugin, "sandbox.h")
            shutil.copyfile(src, dst)
        else:
            self.err_msg("Cannot find real PoC function")
        return feature
    
    def generate_new_PoC(self, features, testcase_path):
        self.info_msg("Generating PoC_repeat.c and PoC_no_repeat.c")
        syz_prog_path = testcase_path
        prog2c_cmd = self._make_prog2c_command(syz_prog_path, features, self.i386)
        self.logger.info("syz-prog2c for PoC_repeat: {}".format(prog2c_cmd))
        local_command(command='chmod +x syz-prog2c && {} > {}/repro.cprog'.format(prog2c_cmd, self.crash_path), logger=self.logger,\
                shell=True, cwd=self.path_case_plugin)
    
    def generate_low_priv_file(self, testcase_path):
        crash_path = os.path.dirname(testcase_path)
        with open(crash_path+"/repro.low-privilege", 'w') as f:
            f.write("true")
        return

    def generate_report(self):
        final_report = "\n".join(self.report)
        self.info_msg(final_report)
        self._write_to(final_report, self.REPORT_NAME)
    
    def _write_to(self, content, name):
        file_path = "{}/{}".format(self.path_case_plugin, name)
        super()._write_to(content, file_path)

    def cleanup(self):
        super().cleanup()

    def _file_is_empty(self, file):
        return open(file, 'r').read() == ''
        
    def _get_syz_features(self, syz_repro):
        enabled_features = []
        for line in syz_repro.split('\n'):
            if line.find('{') != -1 and line.find('}') != -1:
                try:
                    pm = json.loads(line[1:])
                except json.JSONDecodeError:
                    self.case_logger.info("Using old syz_repro")
                    pm = syzrepro_convert_format(line[1:])
                
                if "tun" in pm and str(pm["tun"]).lower() == "true":
                    enabled_features.append("tun")
                if "binfmt_misc" in pm and str(pm["binfmt_misc"]).lower() == 'true':
                    enabled_features.append("binfmt_misc")
                if "cgroups" in pm and str(pm["cgroups"]).lower() == "true":
                    enabled_features.append("cgroups")
                if "close_fds" in pm and str(pm["close_fds"]).lower() == "true":
                    enabled_features.append("close_fds")
                if "devlinkpci" in pm and str(pm["devlinkpci"]).lower() == "true":
                    enabled_features.append("devlinkpci")
                if "netdev" in pm and str(pm["netdev"]).lower() == "true":
                    enabled_features.append("netdev")
                if "resetnet" in pm and str(pm["resetnet"]).lower() == "true":
                    enabled_features.append("resetnet")
                if "usb" in pm and str(pm["usb"]).lower() == "true":
                    enabled_features.append("usb")
                if "ieee802154" in pm and str(pm["ieee802154"]).lower() == "true":
                    enabled_features.append("ieee802154")
                if "sysctl" in pm and str(pm["sysctl"]).lower() == "true":
                    enabled_features.append("sysctl")
                if "vhci" in pm and str(pm["vhci"]).lower() == "true":
                    enabled_features.append("vhci")
                if "wifi" in pm and str(pm["wifi"]).lower() == "true":
                    enabled_features.append("wifi")
                break
        self.info_msg("Enabled features: {}".format(enabled_features))
        for each in enabled_features:
            self.results[each] = True
        return enabled_features 
    
    def _minimize_syz_feature(self):
        essential_features = []
        essential_features.append('no_sandbox')
        self.results['no_sandbox'] = False
        if not self._test_feature(None, essential_features):
            essential_features.remove('no_sandbox')
            if not self._test_feature(None, essential_features):
                return None
        if 'no_sandbox' in essential_features:
            self.results['no_sandbox'] = True
        return essential_features
    
    def _test_feature(self, rule_out_feature, essential_features: list, test_c_prog=False, root=True, repeat=False, sandbox=""):
        self.info_msg("=======================================")
        self.info_msg("Testing ruling out feature: {}".format(rule_out_feature))
        self.info_msg("Testing essential feature: {}".format(essential_features))
        new_features = essential_features.copy()
        if rule_out_feature in new_features:
            new_features.remove(rule_out_feature)
        ubuntu = self.cfg.get_kernel_by_name('ubuntu-fuzzing')
        ubuntu.repro.init_logger(self.logger)
        _, triggered, _ = ubuntu.repro.reproduce(func=self._capture_crash, func_args=(new_features, test_c_prog, repeat, sandbox), vm_tag='test feature {}'.format(rule_out_feature),\
            timeout=self.repro_timeout + 100, attempt=self.repro_attempt, root=root, work_dir=self.path_case_plugin, c_hash=self.case_hash)
        self.info_msg("crash triggered: {}".format(triggered))
        return triggered

    def _capture_crash(self, qemu: VM, root:bool, features: list, test_c_prog: bool, repeat: bool, sandbox: str):
        if root:
            user = 'root'
        else:
            user = 'etenal'
        syz_prog_path = os.path.join(self.crash_path, 'repro.prog')
        qemu.upload(user='root', src=[syz_prog_path], dst='/root/testcase', wait=True)
        qemu.command(cmds="echo \"6\" > /proc/sys/kernel/printk", user='root', wait=True)
        
        if test_c_prog:
            prog2c_cmd = self._make_prog2c_command(syz_prog_path, features, self.i386, repeat=repeat)
            local_command(command='chmod +x syz-prog2c && {} > {}/poc.c'.format(prog2c_cmd, self.path_case_plugin), logger=self.logger,\
                shell=True, cwd=self.path_case_plugin)
            self.tune_poc(root)
            self.info_msg("Convert syz-prog to c prog: {}".format(prog2c_cmd))
            if root:
                poc_file = "poc_root.c"
            else:
                poc_file = "poc_normal.c" 
            sandbox_path = os.path.join(self.path_case_plugin, 'sandbox.h')
            qemu.upload(user=user, src=[os.path.join(self.path_case_plugin, poc_file), sandbox_path], dst='~/', wait=True)
            if self.i386:
                qemu.command(cmds="gcc -m32 -pthread -o poc {}".format(poc_file), user=user, wait=True)
            else:
                qemu.command(cmds="gcc -pthread -o poc {}".format(poc_file), user=user, wait=True)
            
            qemu.command(cmds="./poc", user=user, wait=True, timeout=self.repro_timeout)
        else:
            executor_path = os.path.join(self.path_case_plugin, 'syz-executor')
            execprog_path = os.path.join(self.path_case_plugin, 'syz-execprog')
            qemu.upload(user=user, src=[execprog_path, executor_path], dst='/tmp', wait=True)
            qemu.command(cmds="chmod +x /tmp/syz-executor && chmod +x /tmp/syz-execprog", user=user, wait=True, timeout=self.repro_timeout)

            syz_prog = open(syz_prog_path, 'r').readlines()
            cmd = self.make_syz_command(syz_prog, features, self.i386, repeat=repeat, sandbox=sandbox)
            self.info_msg("syz command: {}".format(cmd))
            qemu.command(cmds=cmd, user=user, wait=True, timeout=self.repro_timeout)
        return
    
    def _make_prog2c_command(self, testcase_path, features: list, i386: bool, repeat=True):
        command = "./syz-prog2c -prog {} ".format(testcase_path)
        text = open(testcase_path, 'r').readlines()

        enabled = "-enable="
        normal_pm = {"arch":"amd64", "threaded":"false", "collide":"false", "sandbox":"none", "fault_call":"-1", "fault_nth":"0", "tmpdir":"false", "segv":"false"}
        for line in text:
            if line.find('{') != -1 and line.find('}') != -1:
                pm = {}
                try:
                    pm = json.loads(line[1:])
                except json.JSONDecodeError:
                    pm = syzrepro_convert_format(line[1:])
                for each in normal_pm:
                    if each in pm and pm[each] != "":
                        if each == "sandbox" and 'no_sandbox' in features:
                            continue
                        command += "-" + each + "=" +str(pm[each]).lower() + " "
                        if each == "sandbox" and str(pm[each]).lower() != "none":
                            command += "-tmpdir "
                    else:
                        if each=='arch' and i386:
                            command += "-" + each + "=386" + " "
                if "procs" in pm and str(pm["procs"]) != "1":
                    num = int(pm["procs"])
                    command += "-procs=" + str(num) + " "
                else:
                    command += "-procs=1" + " "
                if repeat:
                    command += "-repeat=" + "0 "
                else:
                    command += "-repeat=" + "1 "
                if "slowdown" in pm and pm["slowdown"] != "":
                    command += "-slowdown=" + "1 "
                #command += "-trace "
                #It makes no sense that limiting the features of syz-execrpog, just enable them all
                
                if "tun" in features:
                    enabled += "tun,"
                    if '-sandbox' not in command:
                        command += "-sandbox=none "
                    if '-tmpdir' not in command:
                        command += "-tmpdir "
                if "binfmt_misc" in features:
                    enabled += "binfmt_misc,"
                    if '-sandbox' not in command:
                        command += "-sandbox=none "
                    if '-tmpdir' not in command:
                        command += "-tmpdir "
                if "cgroups" in features:
                    enabled += "cgroups,"
                    if '-sandbox' not in command:
                        command += "-sandbox=none "
                    if '-tmpdir' not in command:
                        command += "-tmpdir "
                if "close_fds" in features:
                    enabled += "close_fds,"
                if "devlinkpci" in features:
                    enabled += "devlink_pci,"
                if "netdev" in features:
                    enabled += "net_dev,"
                if "resetnet" in features:
                    enabled += "net_reset,"
                if "usb" in features:
                    enabled += "usb,"
                if "ieee802154" in features:
                    enabled += "ieee802154,"
                if "sysctl" in features:
                    enabled += "sysctl,"
                if "vhci" in features:
                    enabled += "vhci,"
                    if '-sandbox' not in command:
                        command += "-sandbox=none "
                    if '-tmpdir' not in command:
                        command += "-tmpdir "
                if "wifi" in features:
                    enabled += "wifi," 
                    if '-sandbox' not in command:
                        command += "-sandbox=none "
                    if '-tmpdir' not in command:
                        command += "-tmpdir "
                
                if enabled[-1] == ',':
                    command += enabled[:-1] + " testcase"
                else:
                    command += "testcase"
                break
        return command

    def make_syz_command(self, text, features: list, i386: bool, repeat=None, sandbox=""):
        command = "/tmp/syz-execprog -executor=/tmp/syz-executor "
        if text[0][:len(command)] == command:
            # If read from repro.command, text[0] was already the command
            return text[0]
        enabled = "-enable="

        normal_pm = {"arch":"amd64", "threaded":"false", "collide":"false", "sandbox":"none", "fault_call":"-1", "fault_nth":"0"}
        for line in text:
            if line.find('{') != -1 and line.find('}') != -1:
                pm = {}
                try:
                    pm = json.loads(line[1:])
                except json.JSONDecodeError:
                    pm = syzrepro_convert_format(line[1:])
                for each in normal_pm:
                    if each in pm and pm[each] != "":
                        if each == "sandbox":
                            if sandbox != "":
                                command += "-" + each + "=" + sandbox + " "
                                continue
                            if 'no_sandbox' in features:
                                continue
                        command += "-" + each + "=" +str(pm[each]).lower() + " "
                    else:
                        if each=='arch' and i386:
                            command += "-" + each + "=386" + " "
                        else:
                            if each == "sandbox":
                                if sandbox != "":
                                    command += "-" + each + "=" + sandbox + " "
                                    continue
                                if 'no_sandbox' in features:
                                    continue
                if "procs" in pm and str(pm["procs"]) != "1":
                    num = int(pm["procs"])
                    command += "-procs=" + str(num*2) + " "
                else:
                    command += "-procs=1" + " "

                if repeat == None:
                    if "repeat" in pm and pm["repeat"] != "":
                        if pm["repeat"] == "0" or pm["repeat"] == True:
                            command += "-repeat=" + "0 "
                        if pm["repeat"] == "1" or pm["repeat"] == False:
                            command += "-repeat=" + "1 "
                elif repeat:
                    command += "-repeat=" + "0 "
                else:
                    command += "-repeat=" + "1 "
                if "slowdown" in pm and pm["slowdown"] != "":
                    command += "-slowdown=" + "1 "
                #It makes no sense that limiting the features of syz-execrpog, just enable them all
                
                if "tun" in features:
                    enabled += "tun,"
                if "binfmt_misc" in features:
                    enabled += "binfmt_misc,"
                if "cgroups" in features:
                    enabled += "cgroups,"
                if "close_fds" in features:
                    enabled += "close_fds,"
                if "devlinkpci" in features:
                    enabled += "devlink_pci,"
                if "netdev" in features:
                    enabled += "net_dev,"
                if "resetnet" in features:
                    enabled += "net_reset,"
                if "usb" in features:
                    enabled += "usb,"
                if "ieee802154" in features:
                    enabled += "ieee802154,"
                if "sysctl" in features:
                    enabled += "sysctl,"
                if "vhci" in features:
                    enabled += "vhci,"
                if "wifi" in features:
                    enabled += "wifi," 
                
                if enabled[-1] == ',':
                    command += enabled[:-1] + " testcase"
                else:
                    command += "testcase"
                break
        return command