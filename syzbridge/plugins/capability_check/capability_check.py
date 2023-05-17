import os, logging
import shutil

from subprocess import Popen, PIPE, STDOUT, call
from dateutil import parser as time_parser
from infra.tool_box import *
from infra.console.message import ConsoleMessage
from modules.vm import VMInstance
from plugins import AnalysisModule
from plugins.syzkaller_interface import SyzkallerInterface

class CapabilityCheck(AnalysisModule):
    NAME = "CapabilityCheck"
    REPORT_START = "======================CapabilityCheck Report======================"
    REPORT_END =   "==================================================================="
    REPORT_NAME = "Report_CapabilityCheck"
    DEPENDENCY_PLUGINS = ["SyzFeatureMinimize"]
    LOG_HEADER = "INFO: Capability found"

    def __init__(self):
        super().__init__()
        self.syz = None
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
            self.err_msg("Fail to build kernel")
            return False
        if not self.build_syzkaller():
            self.err_msg("Fail to build syzkaller")
            return False
        if not self.tune_poc(debug=True):
            self.err_msg("Fail to tune poc")
            return False
        reports = self.get_capability_check_report()
        if reports == None:
            self.err_msg("Fail to get capability check report")
            return True
        self.parse_report(reports)
        self.set_stage_text("Done")
        return True
    
    def get_capability_check_report(self):
        self.set_stage_text("Getting capabilities")
        upstream = self.cfg.get_kernel_by_name(self.kernel)
        if upstream == None:
            self.logger.exception("Fail to get {} kernel".format(self.kernel))
            return None
        qemu = upstream.repro.launch_qemu(self.case_hash, work_path=self.path_case_plugin\
            , log_name="qemu-{}.log".format(upstream.repro.distro_name), timeout=3*60, tag="capability_check")
        qemu.run(alternative_func=self._run_poc, args=())
        qemu.wait()
        report = self._parse_capability_log(qemu.output)
        qemu.destroy()
        return report
    
    def parse_report(self, reports):
        cap_num = {}
        res = True
        for each_report in reports:
            inspect_next = False
            cap_name = each_report['cap_name']
            trace = each_report['trace']
            if cap_name not in cap_num:
                cap_num[cap_name] = 1
            else:
                cap_num[cap_name] += 1
            key_name = '{}-{}'.format(cap_name, cap_num[cap_name])
            for line in trace:
                func, src_file = parse_one_trace(line)
                if func == None or src_file == None:
                    continue
                if func == "":
                    self.err_msg("{} is not a valid trace".format(line))
                    continue
                if func == "capable":
                    self.results[key_name] = False
                    self.report.append("{} is checked by capable(), can not be ignored by user namespace".format(cap_name))
                    self.report.append("".join(trace))
                    res = False
                    break
                if inspect_next:
                    inspect_next = False
                    if self._check_cap_in_file(src_file):
                        self.results[key_name] = False
                        self.report.append("{} is checked by capable(), can not be ignored by user namespace".format(cap_name))
                        self.report.append("".join(trace))
                        res = False
                        break
                
                if func == 'ns_capable' or func == 'ns_capable_noaudit' or func == 'ns_capable_setid' \
                    or func == 'file_ns_capable' or func == 'has_capability' or func == 'has_capability_noaudit':
                        inspect_next = True
            
            if key_name not in self.results:
                self.results[key_name] = True
                self.report.append("{} seems to be bypassable".format(cap_name))
                self.report.append("".join(trace))
        return res
    
    def build_kernel(self):
        self.set_stage_text("Building kernel")
        if self._check_stamp("BUILD_KERNEL") and not self._check_stamp("BUILD_CAPABILITY_CHECK_KERNEL"):
            self._remove_stamp("BUILD_KERNEL")
        exitcode = self.build_env_upstream()
        if exitcode == 2:
            self.err_msg("Patch has been rejected")
            return False
        if exitcode == 1:
            self.err_msg("Fail to build upstream environment")
            return False
        self._create_stamp("BUILD_CAPABILITY_CHECK_KERNEL")
        return True
    
    def build_env_upstream(self):
        patch = os.path.join(self.path_package, "plugins/capability_check/capability.patch")
        json_path = os.path.join(self.path_package, "plugins/capability_check/capability_patch.json")
        smartpatch = os.path.join(self.path_package, "infra/SmartPatch/SmartPatch")
        extra_cmd="python3 {} -linux {} -patch {}".format(smartpatch, os.path.join(self.path_case, "linux-upstream"), json_path)
        return self.build_mainline_kernel(patch=patch, extra_cmd=extra_cmd)
    
    def build_syzkaller(self):
        if self.syz == None:
            self.syz: SyzkallerInterface() = self._init_module(SyzkallerInterface())
            self.syz.prepare_on_demand(self.path_case_plugin)
        if not self._build_syz_logparser(self.syz):
                self.err_msg("Fail to build syz logparser")
                return False
        return True
    
    def generate_report(self):
        final_report = "\n".join(self.report)
        self.info_msg(final_report)
        self._write_to(final_report, self.REPORT_NAME)
    
    def set_history_status(self):
        if self.finish:
            self.set_stage_text("Done")
        else:
            self.set_stage_text("Failed")
    
    def tune_poc(self, debug=True):
        insert_exit_line = -1
        data = []
        write_monitor_controller = False

        if os.path.exists(os.path.join(self.path_case, "PoC_no_repeat.c")):
            src = os.path.join(os.path.join(self.path_case, "PoC_no_repeat.c"))
        else:
            src = os.path.join(self.path_case, "poc.c")
        dst = os.path.join(self.path_case_plugin, "poc.c")
        non_thread_func = ""
        fsrc = open(src, "r")
        fdst = open(dst, "w")
        
        code = fsrc.readlines()
        fsrc.close()
        text = "".join(code)
        if text.find("int main") != -1:
            non_thread_func = r"^(static )?int main"
            poc_func = r"^(static )?int main\(.*\)\n"
        if text.find("void loop") != -1:
            non_thread_func = r"^(static )?void loop\(.*\)\n"
            poc_func = r"^(static )?void loop\(.*\)\n"
        if text.find("void execute_one") != -1:
            non_thread_func = r"^(static )?void loop\(.*\)\n"
            poc_func = r"^(static )?void loop\(.*\)\n"
        if text.find("void execute_call") != -1:
            poc_func = r"^(static )?void execute_call\(.*\)\n"

        # Locate the function actual trigger the bug    
        for i in range(0, len(code)):
            line = code[i]
            if insert_exit_line == i:
                status = "status{}".format(random.randint(0,10000))
                data.append("int {};\n".format(status))
                data.append("wait(&{});\n".format(status))
                data.append("exit(0);\n")
            data.append(line)
            if insert_exit_line != -1 and i < insert_exit_line:
                if 'for (;; iter++) {' in line:
                    data.pop()
                    t = line.split(';')
                    new_line = t[0] + ";iter<1" + t[1] + ";" + t[2]
                    data.append(new_line)
            
            if write_monitor_controller:
                data.append("int debug = {};\n".format(int(debug)))
                data.append("ioctl(0, 0x37778, &debug);\n")
                write_monitor_controller = False
            
            if regx_match(poc_func, line):
                write_monitor_controller = True

            if regx_match(non_thread_func, line):
                insert_exit_line = self._extract_func(i, code)
            
            # Some PoC pause the entire pocess by sleeping a very long time
            # We skip it in order to speed up trace analysis
            sleep_regx = r'^( )+?sleep\((\d+)\);'
            if regx_match(sleep_regx, line):
                time = regx_get(sleep_regx, line, 1)
                if time == None:
                    self.err_msg("Wrong sleep format: {}".format(line))
                    continue
                if int(time) > 5:
                    data.pop()
                    status = "status{}".format(random.randint(0,10000))
                    data.append("int {};\n".format(status))
                    data.append("wait(&{});\n".format(status))
            
            if 'for (procid = 0;' in line:
                    data.pop()
                    t = line.split(';')
                    new_line = t[0] + ";procid<1;" + t[2]
                    data.append(new_line)

        fdst.writelines(data)
        fdst.close()

        return True

    def _extract_func(self, start_line, text):
        n_bracket = 0
        for i in range(start_line, len(text)):
            line = text[i].strip()
            if '{' in line:
                n_bracket += 1
            if '}' in line:
                n_bracket -= 1
                if n_bracket == 0:
                    return i
        return -1

    def _run_poc(self, qemu):
        poc_path = os.path.join(self.path_case_plugin, "poc.c")
        qemu.upload(user="root", src=[poc_path], dst="~/", wait=True)
        if '386' in self.case['manager']:
            qemu.command(cmds="gcc -m32 -pthread -o poc poc.c", user="root", wait=True)
        else:
            qemu.command(cmds="gcc -pthread -o poc poc.c", user="root", wait=True)
        qemu.command(cmds="chmod +x ./poc && ./poc", user="root", wait=True)
        return True
    
    def _parse_capability_log(self, output):
        res = []
        out1 = []
        n = 0
        for i in range(0, len(output)):
            line = output[i]
            if not regx_match(self._regx_cap, line):
                continue
            cap_name = regx_get(self._regx_cap, line, 0)
            out1 = output[i:]
            call_trace = extrace_call_trace(out1, start_with=self.LOG_HEADER)
            self._write_to("\n".join(call_trace), "call_trace.log-{}".format(n))
            self.syz.pull_cfg_for_cur_case("linux-upstream")
            src = os.path.join(self.path_case_plugin, "call_trace.log-{}".format(n))
            dst = os.path.join(self.path_case_plugin, "call_trace.report-{}".format(n))
            self.syz.generate_decent_report(src, dst)
            if not os.path.exists(dst):
                self.logger.error("Cannot generate capability report for {}".format(cap_name))
                return res
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
        file_path = os.path.join(self.path_case, 'linux-upstream', file)
        with open(file_path, 'r') as f:
            text = f.readlines()
            this_line = text[line-1]
            if this_line.find('init_user_ns') != -1:
                return True
            else:
                return False
        return True

    def _build_syz_logparser(self, syz: SyzkallerInterface):
        patch = os.path.join(self.path_package, "plugins/capability_check/syz_logparser.patch")
        if syz.check_binary(binary_name="syz-logparser"):
            return True
        if syz.pull_syzkaller(commit='b8d780ab30ab6ba340c43ad1944096dae15e6e79') != 0:
            self.err_msg("Fail to pull syzkaller")
            return False
        if syz.patch_syzkaller(patch=patch) != 0:
            self.err_msg("Fail to patch syzkaller")
            return False
        syz.build_syzkaller(arch='amd64')
        if syz.build_syzkaller(arch='amd64', component='all') != 0:
            self.err_msg("Fail to build syzkaller")
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
        super().cleanup()
        if self.syz != None:
            self.syz.delete_syzkaller()

