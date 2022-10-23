import os
import shutil

from subprocess import call, Popen, PIPE, STDOUT
from infra.tool_box import *
from dateutil import parser as time_parser
from plugins import AnalysisModule
from plugins.syzkaller_interface import SyzkallerInterface
from infra.config.vendor import Vendor
from .sym_exec import *
from modules.vm.error import *

class Syzscope(AnalysisModule):
    NAME = "Syzscope"
    REPORT_START = "======================Syzscope Report======================"
    REPORT_END =   "==================================================================="
    REPORT_NAME = "Report_Syzscope"
    DEPENDENCY_PLUGINS = ['BugReproduce']

    def __init__(self):
        super().__init__()
        self.syz = None
        self.timeout = None
        self.gdb_port = None
        self.ssh_port = None
        self.qemu_monitor_port = None
        self.max_round = None
        self.exception_count = 0
        self.repro_mode = 0
        self.result = StateManager.NO_ADDITIONAL_USE
        
    def prepare(self):
        try:
            plugin = self.cfg.get_plugin(self.NAME)
            if plugin == None:
                self.err_msg("No such plugin {}".format(self.NAME))
            timeout = int(plugin.timeout)
            max_round = int(plugin.max_round)
            if plugin.repro_mode == 'c':
                repro_mode = 0
            elif plugin.repro_mode == 'syz':
                repro_mode = 1
        except AttributeError:
            self.err_msg("Failed to get timeout or gdb_port or qemu_monitor_port or max_round")
            return False
        return self.prepare_on_demand(timeout, max_round, repro_mode)
    
    def prepare_on_demand(self, timeout, max_round, repro_mode):
        self._prepared = True
        self.timeout = timeout
        self.max_round = max_round
        self.repro_mode = repro_mode
        return True
    
    def success(self):
        return self._move_to_success

    def run(self):
        distros = self._reproducible()
        if len(distros) == 0:
            self.info_msg("The bug is not reproducible on any distros, syzscope will be skipped")
            return True
        for each in distros:
            self.run_symbolic_execution(each)
        return True
    
    def build_kernel(self):
        if self._check_stamp("BUILD_KERNEL") and self._check_stamp("BUILD_CAPABILITY_CHECK_KERNEL"):
            self._remove_stamp("BUILD_KERNEL")
        exitcode = self.build_env_upstream()
        if exitcode == 2:
            self.err_msg("Patch has been rejected")
            return False
        if exitcode == 1:
            self.err_msg("Fail to build upstream environment")
            return False
        if exitcode != 0:
            self.err_msg("Unknown error that fails to build kernel")
            return False
        return True
    
    def build_env_upstream(self):
        image = "stretch"
        gcc_version = set_compiler_version(time_parser.parse(self.case["time"]), self.case["config"])
        script = os.path.join(self.path_package, "scripts/deploy-linux.sh")
        chmodX(script)

        kernel = self.case["kernel"]
        try:
            if self.case["kernel"].startswith("https"):
                kernel = self.case["kernel"].split('/')[-1].split('.')[0]
        except:
            pass

        p = Popen([script, gcc_version, self.path_case, str(self.args.parallel_max), self.case["commit"], self.case["config"], 
            image, "", "", str(self.index), kernel, ""],
            stderr=STDOUT,
            stdout=PIPE)
        with p.stdout:
            self._log_subprocess_output(p.stdout)
        exitcode = p.wait()
        self.info_msg("script/deploy.sh is done with exitcode {}".format(exitcode))
        return exitcode
    
    def run_symbolic_execution(self, distro: Vendor):
        sub_dir = os.path.join(self.path_case_plugin, distro.distro_name)
        os.makedirs(sub_dir, exist_ok=True)
        if self._check_distro_port(distro):
            self.err_msg("{} doesn't have one of the following port in configuration file: ssh_port, gdb_port, mon_port".format(distro.distro_name))
            return
        
        for i in range(0, self.max_round):
            self.info_msg("Round {}: {} symbolic execution".format(i, distro.distro_name))
            sym_logger = init_logger(sub_dir+"/symbolic_execution.log-{}".format(i), cus_format='%(asctime)s %(message)s', debug=self.debug)
            sym = SymExec(syzscope=self, logger=sym_logger, workdir=self.path_case_plugin, index=0, debug=self.debug)
            qemu = sym.setup_vm(timeout=5*60, log_suffix="-{}".format(i), distro=distro, work_path=sub_dir)
            sym.prepare_angr()
            qemu.run(alternative_func=self._run_sym, args=(sym, sym_logger, ))
            ready_for_sym_exec = qemu.wait()
            sym.cleanup()
            del sym
            if not ready_for_sym_exec:
                continue
            else:
                break

        if self.max_round == self.exception_count:
            return 1
        if self.result & StateManager.CONTROL_FLOW_HIJACK:
            msg = "Control flow hijack found"
            sym_logger.warning(msg)
            self.report.append(msg)
        if self.result & StateManager.ARBITRARY_VALUE_WRITE:
            msg = "Arbitrary value write found"
            sym_logger.warning(msg)
            self.report.append(msg)
        if self.result & StateManager.FINITE_VALUE_WRITE:
            msg = "Constrained value write found"
            sym_logger.warning(msg)
            self.report.append(msg)
        if self.result & StateManager.ARBITRARY_ADDR_WRITE:
            msg = "Arbitrary address write found"
            sym_logger.warning(msg)
            self.report.append(msg)
        if self.result & StateManager.FINITE_ADDR_WRITE:
            msg = "Constrained address write found"
            sym_logger.warning(msg)
            self.report.append(msg)
        if self.result & StateManager.OOB_UAF_WRITE:
            msg = "OOB/UAF write found"
            sym_logger.warning(msg)
            self.report.append(msg)
        if self.result & StateManager.INVALID_FREE:
            msg = "Invalid free found"
            sym_logger.warning(msg)
            self.report.append(msg)
        return self.result == StateManager.NO_ADDITIONAL_USE

    def _run_sym(self, qemu, sym: SymExec, sym_logger):
        try:
            sym.setup_gdb_and_monitor(qemu)
        except QemuIsDead:
            sym_logger.error("Error occur when executing symbolic tracing: QemuIsDead")
            qemu.kill_proc_by_port(self.ssh_port)
            return False
        except AngrRefuseToLoadKernel:
            sym_logger.error("Error occur when loading kernel into angr: AngrRefuseToLoadKernel")
            return False
        except KasanReportEntryNotFound:
            sym_logger.warning("Kasan report entry not found")
            return False
        except Exception as e:
            sym_logger.error("Unknown error occur: {}".format(e))
            return False
        sym_logger.info("Uploading poc and triggering the crash")
        self._run_poc(qemu, self.repro_mode)
        try:
            ret = sym.run_sym(timeout=self.timeout)
            if ret == None:
                sym_logger.warning("Can not locate the vulnerable memory")
                return False
            self.result |= ret
            if ret == 0:
                sym_logger.warning("No additional use")
        except VulnerabilityNotTrigger:
            sym_logger.warning("Can not trigger vulnerability. Abaondoned")
            self.exception_count += 1
            return False
        except AbnormalGDBBehavior:
            sym_logger.warning("Abnormal GDB behavior occured")
            self.exception_count += 1
            return False
        except QemuIsDead:
            sym_logger.error("Error occur when executing symbolic tracing: QemuIsDead")
            self.exception_count += 1
            return False
        except InvalidCPU:
            sym_logger.error("Fail to determine which cpu is using for current context")
            self.exception_count += 1
            return False
        except Exception as e:
            sym_logger.error("Unknown error occur: {}".format(e))
            self.exception_count += 1
            return False
        return True

    def _run_poc(self, qemu, mode=0):
        if mode == 0:
            poc_path = os.path.join(self.path_case_plugin, "poc")
            poc_script_path = os.path.join(self.path_case_plugin, "run_poc.sh")

            args = ['--build', None, '--output', None]
            args[1] = os.path.join(self.path_case, "BugReproduce", "results.json")
            args[3] = self.path_case_plugin

            if os.path.exists(args[1]):
                self.info_msg("call syzmorph: poc {}".format(args))
                out = self.manager.call_syzmorph('poc', args)
                self.info_msg("\n".join(out))
                check_feature_script_path = os.path.join(self.path_case_plugin, "check-poc-feature.sh")
                qemu.upload(user="root", src=[poc_path, poc_script_path, check_feature_script_path], dst="/root", wait=True)
                qemu.command(cmds="chmod +x ./run_poc.sh && ./run_poc.sh", user="root", wait=False)
                return
            
            poc_script = """
#!/bin/bash

set -ex

echo 140800 >  /sys/kernel/debug/tracing/buffer_size_kb
chmod +x ./poc
while :
do
    nohup ./poc > nohup.out 2>&1 &
    sleep 1
done
"""
            self._write_to(poc_script, "run_poc.sh")
            src = os.path.join(self.path_case, "poc.c")
            dst = os.path.join(self.path_case_plugin, "poc.c")
            shutil.copyfile(src, dst)
            call(["gcc", "-pthread", "-static", "-o", "poc", "poc.c"], cwd=self.path_case_plugin)
            qemu.upload(user="root", src=[poc_path, poc_script_path], dst="/root", wait=True)
            qemu.command(cmds="chmod +x ./run_poc.sh && ./run_poc.sh", user="root", wait=False)
        elif mode == 1:
            self.syz =  self._init_module(SyzkallerInterface())
            self.syz.prepare_on_demand(self.path_case_plugin)
            self.syz.pull_syzkaller(commit=self.case['syzkaller'])
            self.syz.build_syzkaller()
            support_enable_feature = self.syz.support_enable_feature()
            r = request_get(self.case['syz_repro'])
            text = r.text.split('\n')
            self._write_to(r.text, "testcase")
            i386 = False
            if regx_match(r'386', self.case["manager"]):
                i386 = True
            command = self.make_commands(text, support_enable_feature, i386)
            target = os.path.join(self.path_package, "scripts/deploy-syz-repro.sh")
            chmodX(target)
            p = Popen([target, command, self.path_case_plugin],
            stdout=PIPE,
            stderr=STDOUT)
            with p.stdout:
                log_anything(p.stdout, self.logger, self.debug)
            
            script_path = os.path.join(self.path_case_plugin, "run_poc.sh")
            testcase_path = os.path.join(self.path_case_plugin, "testcase")
            qemu.upload(user="root", src=[script_path, testcase_path], dst="/root", wait=True)

            execprog_dst = os.path.join(self.path_case_plugin, "syz-execprog")
            executor_dst = os.path.join(self.path_case_plugin, "syz-executor")
            execprog_src = self.syz.get_binary('syz-execprog')
            executor_src = self.syz.get_binary('syz-executor')
            shutil.copyfile(execprog_src, execprog_dst)
            shutil.copyfile(executor_src, executor_dst)
            qemu.upload(user="root", src=[execprog_dst, executor_dst], dst="/", wait=True)
            qemu.command(cmds="chmod +x ./run_poc.sh && ./run_poc.sh", user="root", wait=False)
    
    def make_commands(self, text, support_enable_features, i386):
        command = "/syz-execprog -executor=/syz-executor "
        if text[0][:len(command)] == command:
            # If read from repro.command, text[0] was already the command
            return text[0]
        enabled = "-enable="
        normal_pm = {"arch":"amd64", "threaded":"false", "collide":"false", "sandbox":"none", "repeat":"0"}
        for line in text:
            if line.find('{') != -1 and line.find('}') != -1:
                pm = {}
                try:
                    pm = json.loads(line[1:])
                except json.JSONDecodeError:
                    self.case_logger.info("Using old syz_repro")
                    pm = syzrepro_convert_format(line[1:])
                for each in normal_pm:
                    if each in pm and pm[each] != "":
                        command += "-" + each + "=" +str(pm[each]).lower() + " "
                    else:
                        if each=='arch' and i386:
                            command += "-" + each + "=386" + " "
                        else:
                            command += "-" + each + "=" +str(normal_pm[each]).lower() + " "
                if "procs" in pm and str(pm["procs"]) != "1":
                    num = int(pm["procs"])
                    command += "-procs=" + str(num*2) + " "
                else:
                    command += "-procs=1" + " "
                if "repeat" in pm and pm["repeat"] != "":
                    command += "-repeat=" + "0 "
                if "slowdown" in pm and pm["slowdown"] != "":
                    command += "-slowdown=" + "1 "
                #It makes no sense that limiting the features of syz-execrpog, just enable them all
                
                if support_enable_features != 2:
                    if "tun" in pm and str(pm["tun"]).lower() == "true":
                        enabled += "tun,"
                    if "binfmt_misc" in pm and str(pm["binfmt_misc"]).lower() == 'true':
                        enabled += "binfmt_misc,"
                    if "cgroups" in pm and str(pm["cgroups"]).lower() == "true":
                        enabled += "cgroups,"
                    if "close_fds" in pm and str(pm["close_fds"]).lower() == "true":
                        enabled += "close_fds,"
                    if "devlinkpci" in pm and str(pm["devlinkpci"]).lower() == "true":
                        enabled += "devlink_pci,"
                    if "netdev" in pm and str(pm["netdev"]).lower() == "true":
                        enabled += "net_dev,"
                    if "resetnet" in pm and str(pm["resetnet"]).lower() == "true":
                        enabled += "net_reset,"
                    if "usb" in pm and str(pm["usb"]).lower() == "true":
                        enabled += "usb,"
                    if "ieee802154" in pm and str(pm["ieee802154"]).lower() == "true":
                        enabled += "ieee802154,"
                    if "sysctl" in pm and str(pm["sysctl"]).lower() == "true":
                        enabled += "sysctl,"
                    if "vhci" in pm and str(pm["vhci"]).lower() == "true":
                        enabled += "vhci,"
                    if "wifi" in pm and str(pm["wifi"]).lower() == "true":
                        enabled += "wifi," 
                
                if enabled[-1] == ',':
                    command += enabled[:-1] + " testcase"
                else:
                    command += "testcase"
                break
        return command
    
    def generate_report(self):
        final_report = "\n".join(self.report)
        self.info_msg(final_report)
        self._write_to(final_report, self.REPORT_NAME)
    
    def cleanup(self):
        super().cleanup()
        if self.syz != None:
            self.syz.delete_syzkaller()
    
    def _check_distro_port(self, distro: Vendor):
        return distro.ssh_port == None or distro.gdb_port == None or distro.mon_port == None

    def _write_to(self, content, name):
        file_path = "{}/{}".format(self.path_case_plugin, name)
        super()._write_to(content, file_path)
    
    def _reproducible(self):
        ret = []
        reproducable_regx = r'(debian|fedora|ubuntu) triggers a (Kasan )?bug: ([A-Za-z0-9_: -/]+) (by normal user|by root user)'
        path_report = os.path.join(self.path_case, "BugReproduce", "Report_BugReproduce")
        if os.path.exists(path_report):
            with open(path_report, "r") as f:
                report = f.readlines()
                for line in report:
                    if regx_match(reproducable_regx, line):
                        distro_name = regx_get(reproducable_regx, line, 0)
                        distro = self.cfg.get_kernel_by_name(distro_name)
                        ret.append(distro)
        return ret

