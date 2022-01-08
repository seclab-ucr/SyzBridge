import os
import shutil

from subprocess import call, Popen, PIPE, STDOUT
from infra.tool_box import *
from dateutil import parser as time_parser
from plugins import AnalysisModule
from .sym_exec import *
from modules.vm.error import *

class Syzscope(AnalysisModule):
    NAME = "Syzscope"
    REPORT_START = "======================Syzscope Report======================"
    REPORT_END =   "==================================================================="
    REPORT_NAME = "Report_Syzscope"
    DEPENDENCY_PLUGINS = []

    def __init__(self):
        super().__init__()
        self.report = []
        self._prepared = False
        self.path_case_plugin = ''
        self._move_to_success = False
        self.timeout = None
        self.gdb_port = None
        self.qemu_monitor_port = None
        self.max_round = None
        self.exception_count = 0
        self.result = StateManager.NO_ADDITIONAL_USE
        
    def prepare(self):
        try:
            plugin = self.cfg.get_plugin(self.NAME)
            if plugin == None:
                self.logger.error("No such plugin {}".format(self.NAME))
            timeout = int(plugin.timeout)
            gdb_port = plugin.gdb_port
            qemu_monitor_port = plugin.qemu_monitor_port
            max_round = int(plugin.max_round)
        except KeyError:
            self.logger.error("Failed to get timeout or gdb_port or qemu_monitor_port or max_round")
            return False
        return self.prepare_on_demand(timeout, gdb_port, qemu_monitor_port, max_round)
    
    def prepare_on_demand(self, timeout, gdb_port, qemu_monitor_port, max_round):
        self._prepared = True
        self.timeout = timeout
        self.gdb_port = gdb_port
        self.qemu_monitor_port = qemu_monitor_port
        self.max_round = max_round
        return True
    
    def success(self):
        return self._move_to_success

    def run(self):
        if not self.build_kernel():
            return False
        self.run_symbolic_execution()
        return None
    
    def build_kernel(self):
        if self._check_stamp("BUILD_KERNEL") and self._check_stamp("BUILD_CAPABILITY_CHECK_KERNEL"):
            self._remove_stamp("BUILD_KERNEL")
        exitcode = self.build_env_upstream()
        if exitcode == 2:
            self.logger.error("Patch has been rejected")
            return False
        if exitcode == 1:
            self.logger.error("Fail to build upstream environment")
            return False
        return True
    
    def build_env_upstream(self):
        image = "stretch"
        gcc_version = set_compiler_version(time_parser.parse(self.case["time"]), self.case["config"])
        script = "syzmorph/scripts/deploy-linux.sh"
        chmodX(script)
        p = Popen([script, gcc_version, self.path_case, str(self.args.parallel_max), self.case["commit"], self.case["config"], 
            image, "", "", str(self.index), self.case["kernel"], ""],
            stderr=STDOUT,
            stdout=PIPE)
        with p.stdout:
            self._log_subprocess_output(p.stdout)
        exitcode = p.wait()
        self.logger.info("script/deploy.sh is done with exitcode {}".format(exitcode))
        return exitcode
    
    def run_symbolic_execution(self):
        for i in range(0, self.max_round):
            self.logger.info("Round {}: Symbolic execution".format(i))
            sym_logger = init_logger(self.path_case_plugin+"/symbolic_execution.log-{}".format(i), cus_format='%(asctime)s %(message)s', debug=self.debug)
            sym = SymExec(syzscope=self, logger=sym_logger, workdir=self.path_case_plugin, index=0, debug=self.debug)
            qemu = sym.setup_vm(gdb_port=self.gdb_port, mon_port=self.qemu_monitor_port, timeout=5*60, log_suffix="-{}".format(i))
            _, qemu_queue = qemu.run(alternative_func=self._run_sym, args=(sym, sym_logger, ))
            ready_for_sym_exec = qemu_queue.get(block=True)
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
            qemu.alternative_func_output.put(False)
            qemu.kill_proc_by_port(self.ssh_port)
            return
        except AngrRefuseToLoadKernel:
            sym_logger.error("Error occur when loading kernel into angr: AngrRefuseToLoadKernel")
            qemu.alternative_func_output.put(False)
            return
        except KasanReportEntryNotFound:
            sym_logger.warning("Kasan report entry not found")
            qemu.alternative_func_output.put(False)
            return
        except Exception as e:
            sym_logger.error("Unknown error occur: {}".format(e))
            qemu.alternative_func_output.put(False)
            return
        sym_logger.info("Uploading poc and triggering the crash")
        self._run_poc(qemu)
        try:
            ret = sym.run_sym(timeout=self.timeout)
            if ret == None:
                sym_logger.warning("Can not locate the vulnerable memory")
                qemu.alternative_func_output.put(False)
                return
            self.result |= ret
            if ret == 0:
                sym_logger.warning("No additional use")
        except VulnerabilityNotTrigger:
            sym_logger.warning("Can not trigger vulnerability. Abaondoned")
            self.exception_count += 1
            qemu.alternative_func_output.put(False)
            return
        except AbnormalGDBBehavior:
            sym_logger.warning("Abnormal GDB behavior occured")
            self.exception_count += 1
            qemu.alternative_func_output.put(False)
            return
        except QemuIsDead:
            sym_logger.error("Error occur when executing symbolic tracing: QemuIsDead")
            self.exception_count += 1
            qemu.alternative_func_output.put(False)
            return
        except InvalidCPU:
            sym_logger.error("Fail to determine which cpu is using for current context")
            self.exception_count += 1
            qemu.alternative_func_output.put(False)
            return
        except Exception as e:
            sym_logger.error("Unknown error occur: {}".format(e))
            self.exception_count += 1
            qemu.alternative_func_output.put(False)
            return
        qemu.alternative_func_output.put(True)

    def _run_poc(self, qemu):
        poc_script = """
#!/bin/bash

set -ex

chmod +x ./poc
while :
do
    nohup ./poc > nohup.out 2>&1 &
done
"""
        self._write_to(poc_script, "run_poc.sh")
        src = os.path.join(self.path_case, "poc.c")
        dst = os.path.join(self.path_case_plugin, "poc.c")
        shutil.copyfile(src, dst)
        call(["gcc", "-pthread", "-static", "-o", "poc", "poc.c"], cwd=self.path_case_plugin)
        poc_path = os.path.join(self.path_case_plugin, "poc")
        poc_script_path = os.path.join(self.path_case_plugin, "run_poc.sh")
        qemu.upload(user="root", src=[poc_path, poc_script_path], dst="/root", wait=True)
        qemu.command(cmds="chmod +x ./run_poc.sh && ./run_poc.sh", user="root", wait=False)
    
    def generate_report(self):
        final_report = "\n".join(self.report)
        self.logger.info(final_report)
        self._write_to(final_report, self.REPORT_NAME)
    
    def _write_to(self, content, name):
        file_path = "{}/{}".format(self.path_case_plugin, name)
        super()._write_to(content, file_path)

