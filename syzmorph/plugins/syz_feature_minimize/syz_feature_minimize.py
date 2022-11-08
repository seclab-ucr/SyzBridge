from ast import Import
import os, logging
import shutil
import threading
import queue

from modules.vm import VM
from infra.tool_box import *
from plugins import AnalysisModule
from plugins.syzkaller_interface import SyzkallerInterface

qemu_output_window = 15

class SyzFeatureMinimize(AnalysisModule):
    NAME = "SyzFeatureMinimize"
    REPORT_START = "======================SyzFeatureMinimize Report======================"
    REPORT_END =   "==================================================================="
    REPORT_NAME = "Report_SyzFeatureMinimize"
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
    
    def build_upstream_kernel(self):
        if self._check_stamp("BUILD_KERNEL") and not self._check_stamp("BUILD_SYZ_FEATURE_MINIMIZE_KERNEL"):
            self._remove_stamp("BUILD_KERNEL")
        ret = self.build_mainline_kernel(keep_ori_config=True)
        if ret == 0:
            self._create_stamp("BUILD_SYZ_FEATURE_MINIMIZE_KERNEL")
        return ret
    
    def build_syzkaller(self):
        syz_commit = self.case['syzkaller']
        self.syz = self._init_module(SyzkallerInterface())
        self.syz.prepare_on_demand(self.path_case_plugin)
        if self.syz.pull_syzkaller(commit=syz_commit) != 0:
            self.err_msg("Failed to pull syzkaller")
            return -1
        arch = 'amd64'
        if self.i386:
            arch = '386'
        if self.syz.build_syzkaller(arch=arch) != 0:
            self.err_msg("Failed to build syzkaller")
            return -1
        return 0
    
    def minimize_syz_feature(self, features):
        self.report.append("PoC originally requires {}".format(features))
        return self._minimize_syz_feature(features)
    
    def test_two_prog(self, features):
        if self._test_feature(None, features, repeat=True):
            return self.SYZ_PROG
        if self.test_PoC(features, repeat=True):
            return self.C_PROG
        return self.BOTH_FAIL
    
    def get_features(self):
        syz_repro_url = self.case['syz_repro']
        syz_repro = request_get(syz_repro_url).text
        self._write_to(syz_repro, "testcase")
        syzbin_folder = 'linux_amd64'
        if regx_match(r'386', self.case["manager"]):
            syzbin_folder = 'linux_386'
        shutil.copyfile(os.path.join(self.syz.syzkaller_path, 'bin/linux_amd64/syz-execprog'.format(syzbin_folder)), os.path.join(self.path_case_plugin, 'syz-execprog'))
        shutil.copyfile(os.path.join(self.syz.syzkaller_path, 'bin/{}/syz-executor'.format(syzbin_folder)), os.path.join(self.path_case_plugin, 'syz-executor'))
        shutil.copyfile(os.path.join(self.syz.syzkaller_path, 'bin/syz-prog2c'), os.path.join(self.path_case_plugin, 'syz-prog2c'))

        features = self._get_syz_features(syz_repro)
        return features

    def run(self):
        self.i386 = False
        if regx_match(r'386', self.case["manager"]):
            self.i386 = True
        if self.build_upstream_kernel() != 0:
            self.err_msg("Failed to build upstream kernel")
            return False
        if self.build_syzkaller() < 0:
            self.err_msg('Failed to build syzkaller')
            return False
        features = self.get_features()
        prog_status = self.test_two_prog(features)
        self.results['prog_status'] = prog_status
        self.info_msg("self.results: {} {}".format(self.results, self))
        if prog_status == self.BOTH_FAIL:
            return False
        if prog_status == self.C_PROG:
            self.generate_new_PoC(features)
            return True
        features = self.minimize_syz_feature(features)
        for key in self.results:
            if key not in features and key != 'prog_status':
                self.results[key] = False
        #ret = self.test_PoC(features)
        self.generate_new_PoC(features)
        return True

    def test_PoC(self, features: list, repeat=False):
        if not self._test_feature(None, features, test_c_prog=True, repeat=repeat):
            return False
        return True
    
    def generate_new_PoC(self, features):
        self.info_msg("Generating PoC_repeat.c and PoC_no_repeat.c")
        syz_prog_path = os.path.join(self.path_case_plugin, 'testcase')
        prog2c_cmd = self._make_prog2c_command(syz_prog_path, features, self.i386)
        self.logger.info("syz-prog2c for PoC_repeat: {}".format(prog2c_cmd))
        local_command(command='chmod +x syz-prog2c && {} > {}/PoC_repeat.c'.format(prog2c_cmd, self.path_case_plugin), logger=self.logger,\
                shell=True, cwd=self.syz.path_case_plugin)
        if not self._file_is_empty(os.path.join(self.path_case_plugin, "PoC_repeat.c")):
            shutil.copyfile(os.path.join(self.path_case_plugin, "PoC_repeat.c"), os.path.join(self.path_case, "PoC_repeat.c"))
        
        prog2c_cmd = self._make_prog2c_command(syz_prog_path, features, self.i386, repeat=False)
        self.logger.info("syz-prog2c for PoC_no_repeat: {}".format(prog2c_cmd))
        local_command(command='chmod +x syz-prog2c && {} > {}/PoC_no_repeat.c'.format(prog2c_cmd, self.path_case_plugin), logger=self.logger,\
                shell=True, cwd=self.syz.path_case_plugin)
        if not self._file_is_empty(os.path.join(self.path_case_plugin, "PoC_no_repeat.c")):
            shutil.copyfile(os.path.join(self.path_case_plugin, "PoC_no_repeat.c"), os.path.join(self.path_case, "PoC_no_repeat.c"))

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
    
    def _minimize_syz_feature(self, features: list):
        essential_features = features.copy()
        for rule_out_feature in features:
            if self._test_feature(rule_out_feature, essential_features):
                essential_features.remove(rule_out_feature)
        essential_features.append('no_sandbox')
        self.results['no_sandbox'] = False
        if not self._test_feature(None, essential_features):
            essential_features.remove('no_sandbox')
        if 'no_sandbox' in essential_features:
            self.results['no_sandbox'] = True
        return essential_features
    
    def _test_feature(self, rule_out_feature, essential_features: list, test_c_prog=False, repeat=False, sandbox=""):
        self.info_msg("=======================================")
        self.info_msg("Testing ruling out feature: {}".format(rule_out_feature))
        self.info_msg("Testing essential feature: {}".format(essential_features))
        new_features = essential_features.copy()
        if rule_out_feature in new_features:
            new_features.remove(rule_out_feature)
        upstream = self.cfg.get_kernel_by_name('upstream')
        upstream.repro.init_logger(self.logger)
        _, triggered, _ = upstream.repro.reproduce(func=self._capture_crash, func_args=(new_features, test_c_prog, repeat, sandbox), vm_tag='test feature {}'.format(rule_out_feature),\
            timeout=self.repro_timeout + 100, attempt=self.repro_attempt, root=True, work_dir=self.path_case_plugin, c_hash=self.case_hash)
        self.info_msg("crash triggered: {}".format(triggered))
        return triggered

    def _capture_crash(self, qemu: VM, root:bool, features: list, test_c_prog: bool, repeat: bool, sandbox: str):
        syz_prog_path = os.path.join(self.path_case_plugin, 'testcase')
        qemu.upload(user='root', src=[syz_prog_path], dst='/root', wait=True)
        qemu.command(cmds="echo \"6\" > /proc/sys/kernel/printk", user='root', wait=True)
        
        if test_c_prog:
            prog2c_cmd = self._make_prog2c_command(syz_prog_path, features, self.i386, repeat=repeat)
            local_command(command='chmod +x syz-prog2c && {} > {}/poc.c'.format(prog2c_cmd, self.path_case_plugin), logger=self.logger,\
                shell=True, cwd=self.syz.path_case_plugin)
            self.info_msg("Convert syz-prog to c prog: {}".format(prog2c_cmd))
            qemu.upload(user='root', src=[os.path.join(self.path_case_plugin, 'poc.c')], dst='/root', wait=True)
            if self.i386:
                qemu.command(cmds="gcc -m32 -pthread -o poc poc.c", user="root", wait=True)
            else:
                qemu.command(cmds="gcc -pthread -o poc poc.c", user="root", wait=True)
            
            qemu.command(cmds="./poc", user="root", wait=True, timeout=self.repro_timeout)
        else:
            executor_path = os.path.join(self.path_case_plugin, 'syz-executor')
            execprog_path = os.path.join(self.path_case_plugin, 'syz-execprog')
            qemu.upload(user='root', src=[execprog_path, executor_path], dst='/tmp', wait=True)
            qemu.command(cmds="chmod +x /tmp/syz-executor && chmod +x /tmp/syz-execprog", user='root', wait=True, timeout=self.repro_timeout)

            syz_prog = open(syz_prog_path, 'r').readlines()
            cmd = self.make_syz_command(syz_prog, features, self.i386, repeat=repeat, sandbox=sandbox)
            self.info_msg("syz command: {}".format(cmd))
            qemu.command(cmds=cmd, user='root', wait=True, timeout=self.repro_timeout)
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