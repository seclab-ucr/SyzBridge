import os, logging
import shutil

from subprocess import Popen, PIPE, STDOUT, call
from dateutil import parser as time_parser
from infra.tool_box import *
from modules.vm import VMInstance
from plugins import AnalysisModule
from plugins.syzkaller_interface import SyzkallerInterface

class CapabilityCheck(AnalysisModule):
    NAME = "CapabilityCheck"
    REPORT_START = "======================CapabilityCheck Report======================"
    REPORT_END =   "==================================================================="
    REPORT_NAME = "Report_CapabilityCheck"
    DEPENDENCY_PLUGINS = []
    LOG_HEADER = "INFO: Capability found"

    def __init__(self):
        super().__init__()
        self.syz = None
        self.report = []
        self._prepared = False
        self.path_case_plugin = ''
        self._move_to_success = False
        self._regx_cap = r'thread \d+ request ([A-Z0-9_]+):'
        
    def prepare(self):
        return self.prepare_on_demand()
    
    def prepare_on_demand(self):
        self._prepared = True
        return True
    
    def success(self):
        return self._move_to_success

    def run(self):
        if not self.build_kernel():
            self.logger.error("Fail to build kernel")
            return False
        if not self.tune_poc(debug=True):
            self.logger.error("Fail to tune poc")
            return False
        reports = self.get_capability_check_report()
        if reports == None:
            self.logger.error("Fail to get capability check report")
            return True
        self.parse_report(reports)
        return True
    
    def get_capability_check_report(self):
        upstream = self.cfg.get_upstream()
        qemu = upstream.repro.launch_qemu(self.case_hash, work_path=self.path_case_plugin\
            , log_name="qemu-{}.log".format(upstream.repro.type_name))
        _, qemu_queue = qemu.run(alternative_func=self._run_poc, args=())
        done = qemu_queue.get(block=True)
        report = self._parse_capability_log(qemu.output)
        qemu.kill()
        return report
    
    def parse_report(self, reports):
        res = True
        for each_report in reports:
            inspect_next = False
            cap_name = each_report['cap_name']
            trace = each_report['trace']
            for line in trace:
                func, src_file = parse_one_trace(line)
                if func == None or src_file == None:
                    continue
                if func == "":
                    self.logger.error("{} is not a valid trace".format(line))
                    continue
                if func == "capable":
                    self.report.append("{} is checked by capable(), can not be ignored by user namespace".format(cap_name))
                    self.report.append("".join(trace))
                    res = False
                    break
                if inspect_next:
                    inspect_next = False
                    if self._check_cap_in_file(src_file):
                        self.report.append("{} is checked by capable(), can not be ignored by user namespace".format(cap_name))
                        self.report.append("".join(trace))
                        res = False
                        break
                
                if func == 'ns_capable' or func == 'ns_capable_noaudit' or func == 'ns_capable_setid' \
                    or func == 'file_ns_capable' or func == 'has_capability' or func == 'has_capability_noaudit':
                        inspect_next = True
                
            self.report.append("{} seems to be bypassable".format(cap_name))
            self.report.append("".join(trace))
        return res
    
    def tune_poc(self, debug=True):
        data = []
        src = os.path.join(self.path_case, "poc.c")
        dst = os.path.join(self.path_case_plugin, "poc.c")
        poc_func = ""
        fsrc = open(src, "r")
        fdst = open(dst, "w")

        code = fsrc.readlines()
        fsrc.close()
        text = "".join(code)
        if text.find("int main") != -1:
            poc_func = r"^(static )?int main\(.*\)\n"
        if text.find("void loop") != -1:
            poc_func = r"^(static )?void loop\(.*\)\n"
        if text.find("void execute_call") != -1:
            poc_func = r"^(static )?void execute_call\(.*\)\n"
        for i in range(0, len(code)):
            line = code[i]
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
        if self._check_stamp("BUILD_KERNEL") and not self._check_stamp("BUILD_CAPABILITY_CHECK_KERNEL"):
            self._remove_stamp("BUILD_KERNEL")
        exitcode = self.build_env_upstream()
        if exitcode == 2:
            self.logger.error("Patch has been rejected")
            return False
        if exitcode == 1:
            self.logger.error("Fail to build upstream environment")
            return False
        self._create_stamp("BUILD_CAPABILITY_CHECK_KERNEL")
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

        for i in range(0, 2):
            patch = os.path.join(self.path_package, "plugins/capability_check/capability_check-{}.patch".format(i))
            p = Popen([script, gcc_version, self.path_case, str(self.args.parallel_max), self.case["commit"], self.case["config"], 
                image, "", "", str(self.index), kernel, patch],
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
        poc_script = """
#!/bin/bash

set -ex

chmod +x ./poc
nohup ./poc > nohup.out 2>&1 &

sleep 5
killall poc || true
"""
        self._write_to(poc_script, "run_poc.sh")
        call(["gcc", "-pthread", "-static", "-o", "poc", "poc.c"], cwd=self.path_case_plugin)
        poc_path = os.path.join(self.path_case_plugin, "poc")
        poc_script_path = os.path.join(self.path_case_plugin, "run_poc.sh")
        qemu.upload(user="root", src=[poc_path, poc_script_path], dst="/root", wait=True)
        qemu.command(cmds="chmod +x ./run_poc.sh && ./run_poc.sh", user="root", wait=True)
        qemu.alternative_func_output.put(True)
    
    def _parse_capability_log(self, output):
        res = []
        out1 = []
        n = 0
        if self.syz == None:
            self.syz = self._init_module(SyzkallerInterface())
            self.syz.prepare_on_demand(self.path_case_plugin)
        for i in range(0, len(output)):
            line = output[i]
            if not regx_match(self._regx_cap, line):
                continue
            cap_name = regx_get(self._regx_cap, line, 0)
            out1 = output[i:]
            call_trace = extrace_call_trace(out1, start_with=self.LOG_HEADER)
            self._write_to("\n".join(call_trace), "call_trace.log-{}".format(n))
            if not self._build_syz_logparser(self.syz):
                self.logger.error("Fail to build syz logparser")
                return None
            self.syz.pull_cfg_for_cur_case()
            src = os.path.join(self.path_case_plugin, "call_trace.log-{}".format(n))
            dst = os.path.join(self.path_case_plugin, "call_trace.report-{}".format(n))
            self.syz.generate_decent_report(src, dst)
            f = open(dst, "r")
            txt = f.readlines()
            f.close()
            n += 1
            res.append({'cap_name':cap_name, 'trace':txt})
        return res
    
    def _check_cap_in_file(self, src_file):
        t = src_file.split(':')
        file = t[0]
        line = int(t[1])
        file_path = os.path.join(self.path_case, 'linux', file)
        with open(file_path, 'r') as f:
            text = f.readlines()
            this_line = text[line-1]
            if this_line.find('init_user_ns') != -1:
                return True
            else:
                return False
        return True

    def _build_syz_logparser(self, syz):
        patch = os.path.join(self.path_package, "plugins/capability_check/syz_logparser.patch")
        if syz.check_binary(binary_name="syz-logparser"):
            return True
        if syz.pull_syzkaller(commit=self.case['syzkaller']) != 0:
            self.logger.error("Fail to pull syzkaller")
            return False
        if syz.patch_syzkaller(patch=patch) != 0:
            self.logger.error("Fail to patch syzkaller")
            return False
        """
        Will fail in first time
        sys/sys.go:8:2: cannot find package "." in:
        """
        syz.build_syzkaller()
        if syz.build_syzkaller(component='all') != 0:
            self.logger.error("Fail to build syzkaller")
            return False
        return True
    
    def _create_stamp(self, stamp):
        return super()._create_stamp(stamp)
    
    def _check_stamp(self, stamp):
        return super()._check_stamp(stamp)
    
    def _remove_stamp(self, stamp):
        super()._remove_stamp(stamp)

    def _write_to(self, content, name):
        file_path = "{}/{}".format(self.path_case_plugin, name)
        super()._write_to(content, file_path)
    
    def cleanup(self):
        if self.syz != None:
            self.syz.delete_syzkaller()

