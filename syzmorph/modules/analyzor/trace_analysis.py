import os
import datetime

from . import AnalysisModule
from syzmorph.modules.vm import VMInstance
from subprocess import Popen, PIPE, STDOUT, call
from dateutil import parser as time_parser
from infra.tool_box import regx_match, chmodX, request_get, set_compiler_version

class TraceAnalysis(AnalysisModule):
    NAME = "TraceAnalysis"
    REPORT_START = "======================TraceAnalysis Report======================"
    REPORT_END =   "==================================================================="
    REPORT_NAME = "Report_TraceAnalysis"

    def __init__(self):
        super().__init__()
        self.report = ''
        
    def prepare(self):
        return self.prepare_on_demand()
    
    def prepare_on_demand(self):
        self._prepared = True
        return True
    
    def success(self):
        return self._move_to_success

    def run(self):
        if not self._prepared:
            self.logger.error("Module {} is not prepared".format(TraceAnalysis.NAME))
            return None
        #trace_vendor = self.get_vendor_trace()
        trace_upstream = self.get_upstream_trace()
        ret = self.analyze_trace(trace_vendor, trace_upstream)
        return ret
    
    def analyze_trace(self, trace1, trace2):
        pass
    
    def build_env_upstream(self):
        image_switching_date = datetime.datetime(2020, 3, 15)
        time = self.case["time"]
        case_time = time_parser.parse(time)
        if image_switching_date <= case_time:
            image = "stretch"
        else:
            image = "wheezy"
        
        gcc_version = set_compiler_version(time_parser.parse(self.case["time"]), self.case["config"])
        script = "syzmorph/scripts/deploy-linux.sh"
        chmodX(script)
        p = Popen([script, gcc_version, self.path_case, str(self.args.parallel_max), 
                self.case["commit"], self.case["config"], image, self.lts['snapshot'], self.lts["version"], str(self.index)],
            stderr=STDOUT,
            stdout=PIPE)
        with p.stdout:
            self._log_subprocess_output(p.stdout)
        exitcode = p.wait()
        self.logger.info("script/deploy.sh is done with exitcode {}".format(exitcode))
        return exitcode

    def get_vendor_trace(self):
        vmtype = getattr(VMInstance, self.cfg.vendor_name.upper())
        return self._get_trace(vmtype)

    def get_upstream_trace(self):
        return self._get_trace(VMInstance.UPSTREAM)
    
    def _run_trace_cmd(self, qemu, trace_filename):
        poc_path = os.path.join(self.path_case, "poc")
        
        syscalls = self._get_trace_functions(qemu)
        cmd = "trace-cmd record -p function_graph "
        for each in syscalls:
            cmd += "-g {} ".format(each)
        cmd += "./poc"
        trace_poc_path = self._generate_script(cmd)

        qemu.upload(user="root", src=[poc_path], dst="/root", wait=True)
        qemu.upload(user="root", src=[trace_poc_path], dst="/root", wait=True)

        qemu.command(cmds="chmod +x trace-poc.sh && ./trace-poc.sh\n", user="root", wait=True)
        qemu.command(cmds="trace-cmd report > trace.report", user="root", wait=True)
        qemu.download(user="root", src=["/root/trace.report"], dst="{}/{}.report".format(self.path_case, trace_filename), wait=True)
        qemu.alternative_func_output.put([True])
    
    def generate_report(self):
        final_report = "\n".join(self.report)
        self.logger.info(final_report)
        self._write_to(final_report, TraceAnalysis.REPORT_NAME)
    
    def _generate_script(self, cmd):
        trace_poc_text = """
#!/bin/bash

set -ex

nohup {} > nohup.out 2>&1 &
for i in {{1..60}}; do
    sleep 2
    cat nohup.out | grep function_graph || continue
    break
done

sleep 10
killall poc

for i in {{1..10}}; do
    sleep 5
    ls trace.dat.cpu* || break
done""".format(cmd)
        script_path = os.path.join(self.path_case, "trace-poc.sh")
        with open(script_path, "w") as f:
            f.write(trace_poc_text)
        return script_path
    
    def _get_trace(self, vmtype):
        if vmtype == VMInstance.UPSTREAM:
            if self.build_env_upstream() != 0:
                self.logger.error("Failed to build upstream environment")
                return None

        self.repro.setup(vmtype)
        qemu = self.repro.launch_qemu(self.case_hash, log_name="qemu-{}".format(self.repro.type_name))
        _, qemu_queue = qemu.run(alternative_func=self._run_trace_cmd, args=("trace-{}".format(self.repro.type_name), ))
        [done] = qemu_queue.get(block=True)

        trace_path = os.path.join(self.path_case, "trace-{}.report".format(self.repro.type_name))
        return trace_path
    
    def _get_trace_functions(self, qemu):
        common_setup_syscalls = ['mmap', 'waitpid', 'kill', 'signal', 'exit']
        syscalls = []
        enabled_syscalls = []
        start = len(qemu.pipe_output)
        qemu.command(cmds="trace-cmd list -f | grep -E  \"^__x64_sys_\"", user="root", wait=True)
        for line in qemu.pipe_output[start:]:
            if line.startswith("__x64_sys_"):
                syscalls.append(line.strip())
        
        req = request_get(url=self.case['c_repro'])
        c_text = req.text
        for each in syscalls:
            call_name = each.split("__x64_sys_")[1]
            if " " + call_name + "(" in c_text:
                if call_name not in common_setup_syscalls and call_name not in enabled_syscalls:
                    enabled_syscalls.append(each)
            if "__NR_"+call_name in c_text:
                if call_name not in common_setup_syscalls and call_name not in enabled_syscalls:
                    enabled_syscalls.append(each)
        return enabled_syscalls

