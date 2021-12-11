import os
import shutil

from plugins import AnalysisModule
from modules.vm import VMInstance
from subprocess import Popen, PIPE, STDOUT, call
from dateutil import parser as time_parser
from infra.tool_box import *
from infra.betterFtrace.trace import Trace, Node
from plugins.error import *

class TraceAnalysis(AnalysisModule):
    NAME = "TraceAnalysis"
    REPORT_START = "======================TraceAnalysis Report======================"
    REPORT_END =   "==================================================================="
    REPORT_NAME = "Report_TraceAnalysis"

    def __init__(self):
        super().__init__()
        self.report = ''
        self._prepared = False
        self._move_to_success = False
        self.path_case_plugin = None
        
    def prepare(self):
        if not self.manager.has_c_repro:
            self.logger.error("Case does not have c reproducer")
            return False
        return self.prepare_on_demand()
    
    def prepare_on_demand(self):
        self._prepared = True
        self.logger = self._get_child_logger(self.case_logger)
        return True
    
    def success(self):
        return self._move_to_success

    def run(self):
        if not self._prepared:
            self.logger.error("Module {} is not prepared".format(self.NAME))
            return None

        for _ in range(0,3):
            for distro in self.cfg.get_distros():
                trace_vendor = self.get_vendor_trace(distro)
                if trace_vendor is None:
                    self.logger.error("Failed to get vendor trace, try again")
                    continue
                break
        for _ in range(0,3):
            trace_upstream = self.get_upstream_trace()
            if trace_upstream is None:
                self.logger.error("Failed to get upstream trace, try again")
                continue
            break

        ret = self.analyze_trace(trace_vendor, trace_upstream)
        return ret
    
    def analyze_trace(self, trace1, trace2):
        """if os.path.exists(os.path.join(self.path_case_plugin, "{}.json".format(trace1))):
            begin_nodes = self.load_trace_from_json(trace1)
            if begin_nodes == None:
                os.remove(os.path.join(self.path_case_plugin, "{}.json".format(trace1)))
                begin_nodes = self.serialize_trace(trace1)
        else:"""
        begin_nodes = self.serialize_trace(trace1)
        for each in begin_nodes:
            each.dump_to_file(self.path_case_plugin + "/better_trace-{}-{}-ubuntu.text".format(each.task, each.pid))
        begin_nodes = self.serialize_trace(trace2)
        for each in begin_nodes:
            each.dump_to_file(self.path_case_plugin + "/better_trace-{}-{}-upstream.text".format(each.task, each.pid))
        req = request_get(url=self.case["report"])
        """use_trace, alloc_trace, free_trace = self._get_trace_from_kasan(req.text.split('\n'))

        if not self.match_trace(use_trace, out1):
            return False
        if not self.match_trace(alloc_trace, out1):
            return False
        if not self.match_trace(free_trace, out1):
            return False"""
        return True
    
    def match_trace(self, kasan_trace, ftrace):
        pass
    
    def _get_trace_from_kasan(self, report):
        use_trace = extrace_call_trace(report)
        alloc_trace = extract_alloc_trace(report)
        free_trace = extract_free_trace(report)
        return use_trace, alloc_trace, free_trace
    
    def serialize_trace(self, trace):
        t = Trace(logger=self.logger, debug=self.debug)
        t.load_tracefile(trace)
        begin_nodes = t.serialize()
        #t.dump_to_json(os.path.join(self.path_case_plugin, "{}.json".format(trace)))
        return begin_nodes
    
    def load_trace_from_json(self, trace):
        nodes = []
        with open(os.path.join(self.path_case_plugin, "{}.json".format(trace)), "r") as f:
            data = f.readlines()
            text = ''
            for line in data:
                if line.strip() == boundary_regx:
                    j = json.loads(text)
                    n = Node(**j)
                    nodes.append(n)
                    text = ''
                    continue
                text += line
        return None
    
    def build_env_upstream(self):
        image = "stretch"
        gcc_version = set_compiler_version(time_parser.parse(self.case["time"]), self.case["config"])
        script = "syzmorph/scripts/deploy-linux.sh"
        chmodX(script)
        p = Popen([script, gcc_version, self.path_case, str(self.args.parallel_max), self.case["commit"], self.case["config"], 
            image, self.lts['snapshot'], self.lts["version"], str(self.index), self.case["kernel"]],
            stderr=STDOUT,
            stdout=PIPE)
        with p.stdout:
            self._log_subprocess_output(p.stdout)
        exitcode = p.wait()
        self.logger.info("script/deploy.sh is done with exitcode {}".format(exitcode))
        return exitcode

    def get_vendor_trace(self, distro):
        return self._get_trace(distro)

    def get_upstream_trace(self):
        return self._get_trace(self.cfg.get_upstream())
    
    def _run_trace_cmd(self, qemu, trace_filename, syz_repro=False):
        if syz_repro:
            syz_execprog = os.path.join(self.path_case_plugin, "syz-execprog")
            syz_executor = os.path.join(self.path_case_plugin, "syz-executor")
            testcase = os.path.join(self.path_case_plugin, "testcase")
            trigger_commands = self.prepare_syzkaller()
        else:
            poc_path = os.path.join(self.path_case_plugin, "poc")
            if os.path.exists(poc_path):
                os.remove(poc_path)
            shutil.copyfile(os.path.join(self.path_case, "poc"), poc_path)
            trigger_commands = "./poc"
        
        syscalls = self._get_trace_functions(qemu)
        cmd = "trace-cmd record -p function_graph "
        for each in syscalls:
            cmd += "-g {} ".format(each)
        cmd += trigger_commands
        trace_poc_path = self._generate_script(cmd)

        if syz_repro:
            qemu.upload(user="root", src=[testcase], dst="/root", wait=True)
            qemu.upload(user="root", src=[syz_executor, syz_execprog], dst="/", wait=True)
        else:
            qemu.upload(user="root", src=[poc_path], dst="/root", wait=True)

        qemu.upload(user="root", src=[trace_poc_path], dst="/root", wait=True)
        if qemu.command(cmds="chmod +x trace-poc.sh && ./trace-poc.sh\n", user="root", wait=True) != 0:
            self.logger.error("Something wrong when running command \"chmod +x trace-poc.sh && ./trace-poc.sh\"")
            qemu.alternative_func_output.put([False])
            return
        if qemu.command(cmds="trace-cmd report > trace.report", user="root", wait=True) != 0:
            self.logger.error("Timeout running command \"trace-cmd report > trace.report\"")
            qemu.alternative_func_output.put([False])
            return
        if qemu.download(user="root", src=["/root/trace.report"], dst="{}/{}.report".format(self.path_case_plugin, trace_filename), wait=True) != 0:
            self.logger.error("Failed to download trace report from qemu")
            qemu.alternative_func_output.put([False])
            return
        if qemu.download(user="root", src=["/root/trace.dat"], dst="{}/{}.dat".format(self.path_case_plugin, trace_filename), wait=True) != 0:
            self.logger.error("Failed to download trace data from qemu")
            qemu.alternative_func_output.put([False])
            return 
        qemu.alternative_func_output.put([True])
    
    def prepare_syzkaller(self):
        i386 = None
        if regx_match(r'386', self.case["manager"]):
            i386 = True
        exitcode = self._prepare_syzkaller_bin(i386)
        with open(os.path.join(self.path_case_plugin, "testcase"), "r") as f:
            text = f.readlines()
            syz_commands = make_syz_commands(text, exitcode, i386, repeat=False)
            return syz_commands
        return None
    
    def _prepare_syzkaller_bin(self, i386):
        script = "syzmorph/scripts/deploy-syzkaller.sh"
        chmodX(script)
        p = Popen([script, self.path_case_plugin, self.case["syz_repro"], self.case["syzkaller"], "0", str(i386)],
            stderr=STDOUT,
            stdout=PIPE)
        with p.stdout:
            self._log_subprocess_output(p.stdout)
        exitcode = p.wait()
        self.logger.info("script/deploy-syzkaller.sh is done with exitcode {}".format(exitcode))
        if exitcode != 2 and exitcode != 3:
            return 0
        return exitcode
    
    def generate_report(self):
        final_report = "\n".join(self.report)
        self.logger.info(final_report)
        self._write_to(final_report, self.REPORT_NAME)
    
    def _generate_script(self, cmd):
        trace_poc_text = """
#!/bin/bash

set -ex

echo 140800 >  /sys/kernel/debug/tracing/buffer_size_kb
chmod +x ./poc
nohup {} > nohup.out 2>&1 &
for i in {{1..60}}; do
    sleep 2
    cat nohup.out | grep function_graph || continue
    break
done

sleep 3
killall poc || true

for i in {{1..20}}; do
    sleep 5
    ls trace.dat.cpu* || break
done""".format(cmd)
        script_path = os.path.join(self.path_case_plugin, "trace-poc.sh")
        with open(script_path, "w") as f:
            f.write(trace_poc_text)
        return script_path
    
    def _get_trace(self, vmtype):
        self.repro.setup(vmtype)
        trace_path = os.path.join(self.path_case_plugin, "trace-{}.report".format(self.repro.type_name))
        if os.path.exists(trace_path):
            return trace_path
        if vmtype == VMInstance.UPSTREAM:
            if self.build_env_upstream() != 0:
                self.logger.error("Failed to build upstream environment")
                return None

        qemu = self.repro.launch_qemu(self.case_hash, work_path=self.path_case_plugin, log_name="qemu-{}.log".format(self.repro.type_name))
        _, qemu_queue = qemu.run(alternative_func=self._run_trace_cmd, args=("trace-{}".format(self.repro.type_name), ))
        [done] = qemu_queue.get(block=True)
        qemu.kill()
        if not done:
            return None
        return trace_path
    
    def _get_trace_functions(self, qemu):
        common_setup_syscalls = ['mmap', 'waitpid', 'kill', 'signal', 'exit', 'unshare', 'setrlimit', 'chdir', 'chmod', ]
        syscalls = []
        enabled_syscalls = ['process_one_work', 'do_kern_addr_fault']
        output = qemu.command(cmds="trace-cmd list -f | grep -E  \"^__x64_sys_\"", user="root", wait=True)
        for line in output:
            if line.startswith("__x64_sys_"):
                syscalls.append(line.strip())
        
        req = request_get(url=self.case['c_repro'])
        c_text = req.text
        for each in syscalls:
            group = [each]
            if each == '__x64_sys_recv':
                group = ['__x64_sys_recv', '__x64_sys_recvfrom']
            if each == '__x64_sys_send':
                group = ['__x64_sys_send', '__x64_sys_sendto']
            call_name = each.split("__x64_sys_")[1]
            if regx_match(r'(\W|^){}\('.format(call_name), c_text):
                if call_name not in common_setup_syscalls and each not in enabled_syscalls:
                    enabled_syscalls.extend(group)
            if "__NR_"+call_name in c_text:
                if call_name not in common_setup_syscalls and each not in enabled_syscalls:
                    enabled_syscalls.extend(group)
            if "sys_"+call_name in c_text:
                if call_name not in common_setup_syscalls and each not in enabled_syscalls:
                    enabled_syscalls.extend(group)
        return enabled_syscalls
    
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

