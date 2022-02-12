import os
import shutil

from plugins import AnalysisModule
from modules.vm import VMInstance
from subprocess import Popen, PIPE, STDOUT, call
from dateutil import parser as time_parser
from infra.tool_box import *
from infra.ftraceparser.trace import Trace, Node
from plugins.error import *

class TraceAnalysis(AnalysisModule):
    NAME = "TraceAnalysis"
    REPORT_START = "======================TraceAnalysis Report======================"
    REPORT_END =   "==================================================================="
    REPORT_NAME = "Report_TraceAnalysis"
    DEPENDENCY_PLUGINS = []

    def __init__(self):
        super().__init__()
        self.report = ''
        self.syzcall2syscall = {}
        self._prepared = False
        self._move_to_success = False
        self.path_case_plugin = None
        
    def prepare(self):
        if not self.manager.has_c_repro:
            self.logger.error("Case does not have c reproducer")
            return False
        syzcalljson = os.path.join(self.path_package, "plugins/trace_analysis/syzcall2syscall.json")
        if not os.path.exists(syzcalljson):
            self.logger.error("Cannot find syzcall2syscall.json")
            return False
        self.syzcall2syscall = json.load(open(syzcalljson, "r"))
        return self.prepare_on_demand()
    
    def prepare_on_demand(self):
        self._prepared = True
        return True
    
    def success(self):
        return self._move_to_success

    def run(self):
        if not self._prepared:
            self.logger.error("Module {} is not prepared".format(self.NAME))
            return False

        for _ in range(0,3):
            self.logger.error("Starting retrieving trace from upstream")
            cfg = self.cfg.get_upstream()
            if cfg == None:
                break
            trace_upstream = self._get_trace(cfg)
            if trace_upstream is None:
                self.logger.error("Failed to get upstream trace, try again")
                continue
            break
        for distro in self.cfg.get_distros():
            for _ in range(0,3):
                self.logger.error("Starting retrieving trace from {}".format(distro.distro_name))
                trace_vendor = self._get_trace(distro)
                if trace_vendor is None:
                    self.logger.error("Failed to get vendor trace, try again")
                    continue
                break

        #ret = self.analyze_trace(trace_vendor, trace_upstream)
        return True
    
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
            image, "", "", str(self.index), self.case["kernel"], ""],
            stderr=STDOUT,
            stdout=PIPE)
        with p.stdout:
            self._log_subprocess_output(p.stdout)
        exitcode = p.wait()
        self.logger.info("script/deploy.sh is done with exitcode {}".format(exitcode))
        return exitcode
    
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
            trigger_commands = "./poc"
        
        syscalls = self._tune_poc(qemu)
        call(["gcc", "-pthread", "-static", "-o", "poc", "poc.c"], cwd=self.path_case_plugin)
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
        qemu.command(cmds="chmod +x trace-poc.sh && ./trace-poc.sh\n", user="root", wait=True)
        qemu.command(cmds="trace-cmd report > trace.report", user="root", wait=True)
        if qemu.download(user="root", src=["/root/trace.report"], dst="{}/{}.report".format(self.path_case_plugin, trace_filename), wait=True) != 0:
            self.logger.error("Failed to download trace report from qemu")
            qemu.alternative_func_output.put(False)
            return
        if qemu.download(user="root", src=["/root/trace.dat"], dst="{}/{}.dat".format(self.path_case_plugin, trace_filename), wait=True) != 0:
            self.logger.error("Failed to download trace data from qemu")
            qemu.alternative_func_output.put(False)
            return 
        qemu.alternative_func_output.put(True)
    
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

sleep 30
killall poc || true

for i in {{1..30}}; do
    sleep 5
    ls trace.dat.cpu* || break
done""".format(cmd)
        script_path = os.path.join(self.path_case_plugin, "trace-poc.sh")
        with open(script_path, "w") as f:
            f.write(trace_poc_text)
        return script_path
    
    def _get_trace(self, cfg):
        self.logger.info("Generating trace for {}".format(cfg.repro.type_name))
        trace_path = os.path.join(self.path_case_plugin, "trace-{}.report".format(cfg.repro.type_name))
        if os.path.exists(trace_path):
            return trace_path
        if cfg.type == VMInstance.UPSTREAM:
            if self.build_env_upstream() != 0:
                self.logger.error("Failed to build upstream environment")
                return None

        qemu = cfg.repro.launch_qemu(self.case_hash, work_path=self.path_case_plugin, log_name="qemu-{}.log".format(cfg.repro.type_name))
        _, qemu_queue = qemu.run(alternative_func=self._run_trace_cmd, args=("trace-{}".format(cfg.repro.type_name), ))
        done = qemu_queue.get(block=True)
        qemu.kill()
        if not done:
            return None
        return trace_path
    
    def _tune_poc(self, qemu):
        insert_exit_line = -1
        poc_c_text = ""
        data = []

        src = os.path.join(self.path_case, "poc.c")
        dst = os.path.join(self.path_case_plugin, "poc.c")
        poc_func = ""
        non_thread_func = ""
        flag_change_iter = False
        fsrc = open(src, "r")
        fdst = open(dst, "w")

        common_setup_syscalls = ['mmap', 'waitpid', 'kill', 'signal', 'exit', 'unshare', 'setrlimit', 'chdir', 'chmod', 
           'clone', 'prctl', 'mprotect', 'chroot', '' ]
        devices_init_func_regx = ['initialize_vhci\(\);', 'initialize_netdevices_init\(\);', 'initialize_devlink_pci\(\);',
            'initialize_tun\(\);', 'initialize_netdevices\(\);', 'initialize_wifi_devices\(\);']
        syscalls = []
        enabled_syscalls = ['process_one_work', 'do_kern_addr_fault']
        output = qemu.command(cmds="trace-cmd list -f | grep -E  \"^__x64_sys_\"", user="root", wait=True)
        for line in output:
            if line.startswith("__x64_sys_"):
                syscalls.append(line.strip())
        
        code = fsrc.readlines()
        fsrc.close()
        text = "".join(code)
        if text.find("int main") != -1:
            poc_func = r"^(static )?int main\(.*\)\n"
            non_thread_func = r"^(static )?int main"
        if text.find("void loop") != -1:
            poc_func = r"^(static )?void loop\(.*\)\n"
            non_thread_func = r"^(static )?void loop\(.*\)\n"
        if text.find("void execute_one") != -1:
            non_thread_func = r"^(static )?void loop\(.*\)\n"
            flag_change_iter = True
        if text.find("void execute_call") != -1:
            poc_func = r"^(static )?void execute_call\(.*\)\n"

        # Locate the function actual trigger the bug    
        for i in range(0, len(code)):
            line = code[i]
            if insert_exit_line == i:
                data.append("exit(0);\n")
            data.append(line)
            if insert_exit_line != -1 and i < insert_exit_line:
                if 'for (;; iter++) {' in line:
                    data.pop()
                    t = line.split(';')
                    new_line = t[0] + ";iter<1" + t[1] + ";" + t[2]
                    data.append(new_line)
            # target bug triggering function
            if regx_match(poc_func, line):
                start_line = i+2
                end_line = self._extract_func(i, code)
                poc_c_text = "\n".join(code[start_line:end_line])
            
            if regx_match(non_thread_func, line):
                insert_exit_line = self._extract_func(i, code)
            
            # tune netdevice init function
            for each in devices_init_func_regx:
                if regx_match(each, line):
                    data.insert(len(data)-1, "system(\"echo 0 > /sys/kernel/debug/tracing/tracing_on\");\n")
                    data.insert(len(data)-1, "system(\"echo 0 > /proc/sys/kernel/ftrace_enabled\");\n")
                    data.append("system(\"echo 1 > /sys/kernel/debug/tracing/tracing_on\");\n")
                    data.append("system(\"echo 1 > /proc/sys/kernel/ftrace_enabled\");\n")
                    break

        if poc_c_text == "":
            poc_c_text = text
            fdst.writelines(text)
            fdst.close()
        else:
            fdst.writelines(data)
            fdst.close()

        for each in syscalls:
            group = [each]
            if each == '__x64_sys_recv':
                group = ['__x64_sys_recv', '__x64_sys_recvfrom']
            if each == '__x64_sys_send':
                group = ['__x64_sys_send', '__x64_sys_sendto']
            call_name = each.split("__x64_sys_")[1]
            if regx_match(r'(\W|^){}\('.format(call_name), poc_c_text):
                if each not in enabled_syscalls:
                    enabled_syscalls.extend(group)
            if "__NR_"+call_name+"," in poc_c_text:
                if each not in enabled_syscalls:
                    enabled_syscalls.extend(group)
            if "sys_"+call_name+"," in poc_c_text:
                if each not in enabled_syscalls:
                    enabled_syscalls.extend(group)
        for syzcall in self.syzcall2syscall:
            if syzcall in poc_c_text:
                enabled_syscalls.extend(self.syzcall2syscall[syzcall])
        return unique(enabled_syscalls)
    
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

    def _write_to(self, content, name):
        file_path = "{}/{}".format(self.path_case_plugin, name)
        super()._write_to(content, file_path)

