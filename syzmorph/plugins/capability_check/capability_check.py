import os, logging
import shutil

from subprocess import Popen, PIPE, STDOUT, call
from dateutil import parser as time_parser
from infra.tool_box import *
from modules.vm import VMInstance
from plugins import AnalysisModule

class CapabilityCheck(AnalysisModule):
    NAME = "CapabilityCheck"
    REPORT_START = "======================CapabilityCheck Report======================"
    REPORT_END =   "==================================================================="
    REPORT_NAME = "Report_CapabilityCheck"

    def __init__(self):
        super().__init__()
        self.report = ''
        self._prepared = False
        self.path_case_plugin = ''
        self._move_to_success = False
        self.logger = None
        
    def prepare(self):
        return self.prepare_on_demand()
    
    def prepare_on_demand(self):
        self._prepared = True
        self.logger = self._get_child_logger(self.case_logger)
        return True
    
    def success(self):
        return self._move_to_success

    def run(self):
        if not self.build_kernel():
            return None
        if not self.tune_poc(debug=True):
            return None
        report = self.get_capability_check_report()
        self.parse_report(report)
        return None
    
    def get_capability_check_report(self):
        qemu = self.repro.launch_qemu(self.case_hash, work_path=self.path_case_plugin\
            , log_name="qemu-{}.log".format(self.repro.type_name))
        _, qemu_queue = qemu.run(alternative_func=self._run_poc, args=())
        for line in qemu.output:
            pass
        [done] = qemu_queue.get(block=True)
        qemu.kill()
        if not done:
            return None
        return report
    
    def tune_poc(self, debug=False):
        data = []
        src = os.path.join(self.path_case, "poc.c")
        dst = os.path.join(self.path_case_plugin, "poc.c")
        poc_func = ""
        fsrc = open(src, "r")
        fdst = open(dst, "w")

        code = fsrc.readlines()
        fsrc.close()
        text = "".join(code)
        if text.find("void loop") != -1:
            poc_func = r"^void loop"
        if text.find("void execute_call") != -1:
            poc_func = r"^void execute_call"
        for i in range(0, len(code)):
            line = code[i].strip()
            if regx_match(poc_func, line):
                start_line = i+2
                data = code[:start_line]
                data.append("int debug = {};\n".format(int(debug)))
                data.append("ioctl(-1, 0x37778, &debug);\n")
                data.extend(code[start_line:])
                break
        if data != []:
            fdst.writelines(data)
            fdst.close()
        else:
            self.logger.error("Cannot find real PoC function")
            return False
        return True
    
    def build_kernel(self):
        self.repro.setup(VMInstance.UPSTREAM)
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
        patch = os.path.join(self.path_package, "plugins/capability_check/capability_check.patch")
        gcc_version = set_compiler_version(time_parser.parse(self.case["time"]), self.case["config"])
        script = "syzmorph/scripts/deploy-linux.sh"
        chmodX(script)
        p = Popen([script, gcc_version, self.path_case, str(self.args.parallel_max), self.case["commit"], self.case["config"], 
            image, self.lts['snapshot'], self.lts["version"], str(self.index), self.case["kernel"], patch],
            stderr=STDOUT,
            stdout=PIPE)
        with p.stdout:
            self._log_subprocess_output(p.stdout)
        exitcode = p.wait()
        self.logger.info("script/deploy.sh is done with exitcode {}".format(exitcode))
        return exitcode
    
    def generate_report(self):
        final_report = "\n".join(self.report)
        self.logger.info(final_report)
        self._write_to(final_report, self.REPORT_NAME)
    
    def _run_poc(self, qemu):
        call(["gcc", "-pthread", "-static", "-o", "poc", "poc.c"], cwd=self.path_case_plugin)
        poc_path = os.path.join(self.path_case_plugin, "poc")
        qemu.upload(user="root", src=[poc_path], dst="/root", wait=True)
        qemu.command(cmds="chmod +x ./poc && ./poc", user="root", wait=False)
    
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

