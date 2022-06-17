import os
import random

from plugins import AnalysisModule
from modules.vm import VMInstance
from subprocess import Popen, PIPE, STDOUT, call
from dateutil import parser as time_parser
from infra.tool_box import *
from infra.ftraceparser.ftraceparser.trace import Trace, Node
from plugins.error import *

TIMEOUT_TRACE_ANALYSIS = 10*60
class TraceAnalysis(AnalysisModule):
    NAME = "TraceAnalysis"
    REPORT_START = "======================TraceAnalysis Report======================"
    REPORT_END =   "==================================================================="
    REPORT_NAME = "Report_TraceAnalysis"
    DEPENDENCY_PLUGINS = []

    def __init__(self):
        super().__init__()
        self.syzcall2syscall = {}
        self.syscall_prefix = '__x64_sys_'
        
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
            if trace_upstream == None:
                self.logger.error("Failed to get upstream trace, try again")
                continue
            if self._is_trace_empty(trace_upstream):
                continue
            break

        if self._is_trace_empty(trace_upstream):
            self.logger.error("Failed to get upstream trace")
            return False
        
        for distro in self.cfg.get_distros():
            for _ in range(0,3):
                self.results[distro.distro_name] = False
                self.logger.info("Starting retrieving trace from {}".format(distro.distro_name))
                trace_vendor = self._get_trace(distro)
                if trace_vendor is None:
                    self.logger.error("Failed to get vendor trace, try again")
                    continue
                if self._is_trace_empty(trace_vendor):
                    continue
                self.results[distro.distro_name] = True
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
        script = os.path.join(self.path_package, "scripts/deploy-linux.sh")
        kernel = self.case["kernel"]
        if len(self.case["kernel"].split(" ")) == 2:
            kernel = self.case["kernel"].split(" ")[0]
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
        self.logger.info("script/deploy.sh is done with exitcode {}".format(exitcode))
        return exitcode
    
    def _run_trace_cmd(self, qemu: VMInstance, trace_filename, syz_repro=False):
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
        p = Popen(["gcc", "-pthread", "-static", "-o", "poc", "poc.c"], cwd=self.path_case_plugin, stdout=PIPE, stderr=PIPE)
        with p.stdout:
            log_anything(p.stdout, self.logger, self.debug)
        exitcode = p.wait()
        if exitcode != 0:
            self.logger.error('Failed to compile poc')
            qemu.alternative_func_output.put(False)
            return
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
        qemu.download(user="root", src=["/root/trace.report"], dst="{}/{}.report".format(self.path_case_plugin, trace_filename), wait=True)
        if qemu.dumped_ftrace:
            self.logger.error("qemu paniced, restoring raw ftrace")
            if self._save_dumped_ftrace(qemu, "{}/raw-{}.report".format(self.path_case_plugin, trace_filename)):
                self._convert_raw_ftrace("{}/raw-{}.report".format(self.path_case_plugin, trace_filename),
                    "{}/{}.report".format(self.path_case_plugin, trace_filename), syscalls)
                qemu.alternative_func_output.put(True)
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
    
    def _save_dumped_ftrace(self, qemu: VMInstance, save_to):
        res = []
        kernel_log_regx = r'\[(( )+)?\d+\.\d+\]\[(( )+)?T(\d+)\] (.+)'
        begin_ftrace = False
        separate_line = 0
        for line in qemu.output:
            line = line.strip()
            if 'Dumping ftrace buffer' in line:
                begin_ftrace = True
                continue
            if begin_ftrace:
                if regx_match(kernel_log_regx, line):
                    text = regx_get(kernel_log_regx, line, 5)
                    if text == '---------------------------------':
                        separate_line ^= 1
                        continue
                    if separate_line:
                        res.append(line+"\n")
                    elif len(res) > 0:
                        break
        with open(save_to, 'w') as f:
            f.writelines(res)
        return len(res)
    
    def _convert_raw_ftrace(self, src, dst, entry_functions):
        trace = Trace()
        trace.convert_ftrace(ftrace_file=src, entry_functions=entry_functions, save_to=dst)

    def _prepare_syzkaller_bin(self, i386):
        script = os.path.join(self.path_package, "scripts/deploy-syzkaller.sh")
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

for i in {{1..720}}; do
    sleep 5
    ls trace.dat.cpu* || break
done

CPU_DATA=0
ls trace.dat.cpu0 && CPU_DATA=1 || true
if [ $CPU_DATA -eq 1 ]; then
    echo "try to manually restore trace.dat"
    CPU_DATA_LIST=`ls trace.dat.cpu*`
    trace-cmd restore -o $CPU_DATA_LIST
fi

EXIT_CODE=0
ls trace.dat || EXIT_CODE=1
exit $EXIT_CODE""".format(cmd)
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

        qemu = cfg.repro.launch_qemu(self.case_hash, work_path=self.path_case_plugin, log_name="qemu-{}.log".format(cfg.repro.type_name), timeout=TIMEOUT_TRACE_ANALYSIS, snapshot=False)
        _, qemu_queue = qemu.run(alternative_func=self._run_trace_cmd, args=("trace-{}".format(cfg.repro.type_name), ))
        done = qemu_queue.get(block=True)
        qemu.kill()
        if not done:
            return None
        return trace_path
    
    def _tune_poc(self, qemu):
        insert_exit_line = -1
        common_entries = ['process_one_work', '__do_softirq', 'do_kern_addr_fault']
        enabled_syscalls = []
        skip_funcs = [r"setup_usb\(\);", r"setup_leak\(\);", r"setup_cgroups\(\);", r"initialize_cgroups\(\);", r"setup_cgroups_loop\(\);"]
        data = []

        src = os.path.join(self.path_case, "poc.c")
        dst = os.path.join(self.path_case_plugin, "poc.c")
        non_thread_func = ""
        fsrc = open(src, "r")
        fdst = open(dst, "w")

        devices_init_func_regx = ['initialize_vhci\(\);', 'initialize_netdevices_init\(\);', 'initialize_devlink_pci\(\);',
            'initialize_tun\(\);', 'initialize_netdevices\(\);', 'initialize_wifi_devices\(\);']
        
        syscalls = []
        output = qemu.command(cmds="trace-cmd list -f | grep -E  \"^__x64_sys_\"", user="root", wait=True)
        for line in output:
            if line.startswith("__x64_sys_"):
                syscalls.append(line.strip())
        if len(syscalls) == 0:
            # try SyS_ prefix
            output = qemu.command(cmds="trace-cmd list -f | grep -E  \"^SyS_\"", user="root", wait=True)
            for line in output:
                if line.startswith("SyS_"):
                    syscalls.append(line.strip())
                    self.syscall_prefix = 'SyS_'
        common_entries.append(self._syscall_add_prefix('exit_group'))
        for each in common_entries:
            output = qemu.command(cmds="trace-cmd list -f | grep -E  \"^{}\"".format(each), user="root", wait=True)
            for line in output:
                if line == each:
                    enabled_syscalls.append(each)
        
        code = fsrc.readlines()
        fsrc.close()
        text = "".join(code)
        if text.find("int main") != -1:
            non_thread_func = r"^(static )?int main"
        if text.find("void loop") != -1:
            non_thread_func = r"^(static )?void loop\(.*\)\n"
        if text.find("void execute_one") != -1:
            non_thread_func = r"^(static )?void loop\(.*\)\n"

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

            for each in skip_funcs:
                if regx_match(each, line):
                    data.pop()
            
            # Some PoC pause the entire pocess by sleeping a very long time
            # We skip it in order to speed up trace analysis
            sleep_regx = r'^( )+?sleep\((\d+)\);'
            if regx_match(sleep_regx, line):
                time = regx_get(sleep_regx, line, 1)
                if time == None:
                    self.logger.error("Wrong sleep format: {}".format(line))
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
            
            """# Somehow if PoC exit too quickly, the trace will not be complete
            exit_regx = r'^( )+?exit\((\d+)\);'
            if regx_match(exit_regx, line):
                data.insert(len(data)-1, "sleep(1);\n")"""

        fdst.writelines(data)
        fdst.close()

        r = request_get(self.case['syz_repro'])
        testcase = self._extract_syscall_from_template(r.text)
        for each in testcase:
            if '$' in each:
                syscall = each.split('$')[0]
            else:
                syscall = each
            
            if self._syscall_add_prefix(syscall) in syscalls: 
                syscall = self._syscall_add_prefix(syscall)
                group = [syscall]
                if syscall == self._syscall_add_prefix('recv'):
                    group = [self._syscall_add_prefix('recv'), self._syscall_add_prefix('recvfrom')]
                if syscall == self._syscall_add_prefix('send'):
                    group = [self._syscall_add_prefix('send'), self._syscall_add_prefix('sendto')]
                if syscall not in enabled_syscalls:
                    enabled_syscalls.extend(group)
            if syscall.startswith("syz_"):
                if syscall in self.syzcall2syscall:
                    for each in self.syzcall2syscall[syscall]:
                        enabled_syscalls.append(self._syscall_add_prefix(each))
        return unique(enabled_syscalls)
    
    def _syscall_add_prefix(self, syscall):
        return self.syscall_prefix+syscall
    
    def _extract_syscall_from_template(self, testcase):
        res = []
        text = testcase.split('\n')
        for line in text:
            if len(line)==0 or line[0] == '#':
                continue
            syscall = regx_get(r'(\w+(\$\w+)?)\(', line, 0)
            if syscall != None:
                res.append(syscall)
        return res

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
    
    def _is_trace_empty(self, trace_path):
        if trace_path == None:
            return True
        if not os.path.exists(trace_path):
            return True
        f = open(trace_path, "r")
        lines = f.readlines()
        f.close()
        if len(lines) == 0:
            return True
        return False

    def _write_to(self, content, name):
        file_path = "{}/{}".format(self.path_case_plugin, name)
        super()._write_to(content, file_path)

