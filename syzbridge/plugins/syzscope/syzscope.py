import os
import shutil
import time

from subprocess import call, Popen, PIPE, STDOUT
from infra.tool_box import *
from modules.vm import VMInstance
from dateutil import parser as time_parser
from plugins import AnalysisModule
from plugins.syz_feature_minimize import SyzFeatureMinimize
from plugins.bug_reproduce import BugReproduce
from infra.config.vendor import Vendor
from .sym_exec import *
from modules.vm.qemu.error import *

class Syzscope(AnalysisModule):
    NAME = "Syzscope"
    REPORT_START = "======================Syzscope Report======================"
    REPORT_END =   "==================================================================="
    REPORT_NAME = "Report_Syzscope"
    DEPENDENCY_PLUGINS = ['BugReproduce', 'SyzFeatureMinimize']
    FEATURE_LOOP_DEVICE = 1 << 0

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
        self._cur_distro = None
        
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
            try:
                self.repro_timeout = int(plugin.repro_timeout)
            except AttributeError:
                self.repro_timeout = 300
            try:
                run_when_distro_success = plugin.run_when_distro_success
            except AttributeError:
                run_when_distro_success = False
        except AttributeError:
            self.err_msg("Failed to get timeout or repro_timeout or gdb_port or qemu_monitor_port or max_round")
            return False
        return self.prepare_on_demand(timeout, max_round, repro_mode, run_when_distro_success)
    
    def prepare_on_demand(self, timeout, max_round, repro_mode, run_when_distro_success):
        self._prepared = True
        self.timeout = timeout
        self.max_round = max_round
        self.repro_mode = repro_mode
        self.run_when_distro_success = run_when_distro_success
        return True
    
    def success(self):
        return self._move_to_success

    def run(self):
        if self.run_when_distro_success:
            allow_syzscope = False
            bug_reproduce = self.cfg.get_plugin(BugReproduce.NAME).instance
            for distro in bug_reproduce.results:
                if bug_reproduce.results[distro]['trigger']:
                    allow_syzscope = True
                    break
            if not allow_syzscope:
                self.logger.info("No distro has been triggered, skip syzscope")
                return True
        self.syz_feature_mini = self.cfg.get_plugin(SyzFeatureMinimize.NAME).instance
        self.syz_feature_mini.path_case_plugin = os.path.join(self.path_case, SyzFeatureMinimize.NAME)
        if not self.plugin_finished("SyzFeatureMinimize"):
            self.logger.error("SyzFeatureMinimize plugin has not finished")
            return False
        self.syz_feature = self.syz_feature_mini.results.copy()
        self.syz_feature.pop('prog_status')
        
        self.build_kernel()
        upstream = self.cfg.get_kernel_by_name(self.kernel)
        if upstream == None:
            self.logger.exception("Fail to get {} kernel".format(self.kernel))
            return False
        self._cur_distro = upstream
        self.run_symbolic_execution(upstream)
        return True
    
    def build_kernel(self):
        if self._check_stamp("BUILD_KERNEL") and not self._check_stamp("BUILD_SYZSCOPE_KERNEL"):
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
        self._create_stamp("BUILD_SYZSCOPE_KERNEL")
        return True
    
    def build_env_upstream(self):
        return self.build_mainline_kernel(keep_ori_config=True)
    
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
        self._execute_syz(qemu)
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

    def _check_poc_feature(self, poc_feature, qemu: VMInstance, user):
        script_name = "check-poc-feature.sh"
        script = os.path.join(self.path_package, "plugins/bug_reproduce", script_name)
        shutil.copy(script, self.path_case_plugin)
        cur_script = os.path.join(self.path_case_plugin, script_name)
        qemu.upload(user=user, src=[cur_script], dst="~/", wait=True)
        qemu.command(cmds="chmod +x check-poc-feature.sh && ./check-poc-feature.sh {}".format(poc_feature), user=user, wait=True)
    
    def _execute_syz(self, qemu: VMInstance):
        user = "root"
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
        testcase_text = open(testcase, "r").readlines()
        
        cmds = self.syz_feature_mini.make_syz_command(testcase_text, self.syz_feature, i386, repeat=True, root=True)
        qemu.command(cmds=cmds, user=user, wait=False, timeout=self.repro_timeout)
        return
    
    def _enable_missing_modules(self, qemu, manual_enable_modules):
        for each in manual_enable_modules:
            args = self._module_args(each)
            out = qemu.command(cmds="modprobe {}{}".format(each, args), user=self.root_user, wait=True, timeout=60)
            time.sleep(5)
        return True
    
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

