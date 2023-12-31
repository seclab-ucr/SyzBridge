import os
import random

from plugins import AnalysisModule
from modules.vm import VMInstance
from subprocess import Popen, PIPE, STDOUT, call
from dateutil import parser as time_parser
from infra.tool_box import *
from infra.ftraceparser.ftraceparser.trace import Trace, Node
from plugins.error import *

class TraceAnalysis(AnalysisModule):
    NAME = "TraceAnalysis"
    REPORT_START = "======================TraceAnalysis Report======================"
    REPORT_END =   "==================================================================="
    REPORT_NAME = "Report_TraceAnalysis"
    DEPENDENCY_PLUGINS = ["SyzFeatureMinimize"]

    def __init__(self):
        super().__init__()
        self.syzcall2syscall = {}
        self.addition_modules = []
        
    def prepare(self):
        plugin = self.cfg.get_plugin(self.NAME)
        if plugin == None:
            self.err_msg("No such plugin {}".format(self.NAME))
        try:
            self.trace_timeout = int(plugin.timeout)
        except AttributeError:
            self.err_msg("Failed to get timeout")
            return False
        syzcalljson = os.path.join(self.path_package, "plugins/trace_analysis/syzcall2syscall.json")
        if not os.path.exists(syzcalljson):
            self.err_msg("Cannot find syzcall2syscall.json")
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
            self.err_msg("Module {} is not prepared".format(self.NAME))
            return False

        for i in range(0,3):
            self.err_msg("Starting retrieving trace from {}".format(self.kernel))
            cfg = self.cfg.get_kernel_by_name(self.kernel)
            if cfg == None:
                self.logger.exception("Fail to get {} kernel".format(self.kernel))
                return False
            if cfg == None:
                break
            trace_upstream = self._get_trace(i, cfg)
            if trace_upstream == None:
                self.err_msg("Failed to get {} trace, try again".format(self.kernel))
                continue
            if self._is_trace_empty(trace_upstream):
                continue
            break

        if self._is_trace_empty(trace_upstream):
            self.err_msg("Failed to get {} trace".format(self.kernel))
            return False
        
        affect_distros = self.cfg.get_distros()
        for i in range(0, len(affect_distros)):
            distro = affect_distros[i]
            for i in range(0,3):
                self.results[distro.distro_name] = False
                self.info_msg("Starting retrieving trace from {}".format(distro.distro_name))
                self.set_stage_text("Getting trace from {} [{}/{}]".format(cfg.repro.distro_name, i, len(affect_distros)))
                trace_vendor = self._get_trace(i, distro)
                if trace_vendor is None:
                    self.err_msg("Failed to get vendor trace, try again")
                    continue
                if self._is_trace_empty(trace_vendor):
                    continue
                self.results[distro.distro_name] = True
                break

        self.set_stage_text("Done")
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
            each.dump_to_file(self.path_case_plugin + "/better_trace-{}-{}-{}.text".format(each.task, each.pid, self.kernel))
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
        if self._check_stamp("BUILD_KERNEL") and not self._check_stamp("BUILD_TRACE_ANALYSIS_KERNEL"):
            self._remove_stamp("BUILD_KERNEL")
        panic_patch = os.path.join(self.path_package, "plugins/trace_analysis/panic.patch")
        ret = self.build_mainline_kernel(patch=panic_patch)
        self._create_stamp("BUILD_TRACE_ANALYSIS_KERNEL")
        return ret
    
    def _run_trace_cmd(self, qemu: VMInstance, trace_filename, syz_repro=False):
        self.set_stage_text("Extracting trace from {}".format(trace_filename))
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
        
        cmd = "trace-cmd record -p function_graph "
        for each in syscalls:
            cmd += "-g {} ".format(each)
        cmd += trigger_commands
        trace_poc_script_name = "trace-poc-{}.sh".format(qemu.tag)
        trace_poc_path = self._generate_script(cmd, trace_poc_script_name)

        if syz_repro:
            qemu.upload(user="root", src=[testcase], dst="/root", wait=True)
            qemu.upload(user="root", src=[syz_executor, syz_execprog], dst="/tmp", wait=True)
        else:
            poc_src = "poc.c"
            poc_path = os.path.join(self.path_case_plugin, poc_src)
            qemu.upload(user="root", src=[poc_path], dst="/root", wait=True)
            if '386' in self.case['manager']:
                qemu.command(cmds="gcc -m32 -pthread -o poc {}".format(poc_src), user="root", wait=True)
            else:
                qemu.command(cmds="gcc -pthread -o poc {}".format(poc_src), user="root", wait=True)

        qemu.upload(user="root", src=[trace_poc_path], dst="/root", wait=True)
        qemu.command(cmds="chmod +x {0} && ./{0}\n".format(trace_poc_script_name), user="root", wait=True)
        qemu.command(cmds="trace-cmd report > trace.report", user="root", wait=True)
        qemu.download(user="root", src=["/root/trace.report"], dst="{}/{}.report".format(self.path_case_plugin, trace_filename), wait=True)
        if qemu.dumped_ftrace:
            self.err_msg("qemu paniced, restoring raw ftrace")
            if self._save_dumped_ftrace(qemu, "{}/raw-{}.report".format(self.path_case_plugin, trace_filename)):
                self._convert_raw_ftrace("{}/raw-{}.report".format(self.path_case_plugin, trace_filename),
                    "{}/{}.report".format(self.path_case_plugin, trace_filename), syscalls)
                return True
        return True
    
    def _retrieve_trace(self, qemu: VMInstance, trace_filename):
        out = qemu.command(cmds="ls trace.dat", user="root", wait=True)
        for line in out:
            if "No such file or directory" in line:
                qemu.command(cmds="CPU_DATA_LIST=`ls trace.dat.cpu*`; trace-cmd restore $CPU_DATA_LIST", user="root", wait=True)
        qemu.command(cmds="trace-cmd report > trace.report", user="root", wait=True)
        qemu.download(user="root", src=["/root/trace.report"], dst="{}/{}.report".format(self.path_case_plugin, trace_filename), wait=True)
        return True

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
        kernel_log_regx = r'\[(( )+)?\d+\.\d+\]\[(( )+)?(T|C|P)(\d+)\] (.+)'
        begin_ftrace = False
        separate_line = 0
        for line in qemu.output:
            line = line.strip()
            if 'Dumping ftrace buffer' in line:
                begin_ftrace = True
                continue
            if begin_ftrace:
                if regx_match(kernel_log_regx, line):
                    text = regx_get(kernel_log_regx, line, 6)
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
        self.info_msg("script/deploy-syzkaller.sh is done with exitcode {}".format(exitcode))
        if exitcode != 2 and exitcode != 3:
            return 0
        return exitcode
    
    def set_history_status(self):
        text = ""
        for distro_name in self.results:
            if not self.results[distro_name]:
                text += "{} failed\n".format(distro_name)
        if text == "":
            self.set_stage_text("Done")
            return
        self.set_stage_text(text)
        return

    def generate_report(self):
        final_report = "\n".join(self.report)
        self.info_msg(final_report)
        self._write_to(final_report, self.REPORT_NAME)
    
    def _generate_script(self, cmd, script_name):
        modprobe_cmd = ""
        for mod in self.addition_modules:
            modprobe_cmd += "modprobe {} || true\n".format(mod)
        trace_poc_text = """
#!/bin/bash

set -ex

{}
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
exit $EXIT_CODE""".format(modprobe_cmd, cmd)
        script_path = os.path.join(self.path_case_plugin, script_name)
        with open(script_path, "w") as f:
            f.write(trace_poc_text)
        return script_path
    
    def _get_trace(self, idx, distro):
        self.set_stage_text("Getting trace from {}".format(distro.distro_name))
        self.info_msg("Generating trace for {}".format(distro.distro_name))
        trace_path = os.path.join(self.path_case_plugin, "trace-{}.report".format(distro.distro_name))
        if os.path.exists(trace_path):
            return trace_path
        if distro.type == VMInstance.UPSTREAM:
            if self.build_env_upstream() != 0:
                self.err_msg("Failed to build {} environment".format(self.kernel))
                return None

        qemu = distro.repro.launch_qemu(self.case_hash, tag="{}-trace".format(distro.distro_name), work_path=self.path_case_plugin, 
        log_name="qemu-{}-{}.log".format(distro.distro_name, idx), timeout=self.trace_timeout, snapshot=False)
        qemu.run(alternative_func=self._run_trace_cmd, args=("trace-{}".format(distro.distro_name), ))
        done = qemu.wait()
        qemu.kill_vm()
        if not os.path.exists(trace_path):
            qemu.run(alternative_func=self._retrieve_trace, args=("trace-{}".format(distro.distro_name), ))
            done = qemu.wait()
        qemu.destroy()
        if not done:
            return None
        return trace_path
    
    def _tune_poc(self, qemu):
        syscall_prefix = '__x64_sys_'
        insert_exit_line = -1
        common_entries = ['process_one_work', '__do_softirq', 'do_kern_addr_fault', 
                'task_work_run']
        enabled_syscalls = []
        skip_funcs = []
        if qemu.tag != "upstream-trace":
            skip_funcs = [r"setup_usb\(\);", r"setup_leak\(\);"]
        data = []

        if os.path.exists(os.path.join(self.path_case, "PoC_no_repeat.c")):
            src = os.path.join(os.path.join(self.path_case, "PoC_no_repeat.c"))
        else:
            src = os.path.join(self.path_case, "poc.c")
        dst = os.path.join(self.path_case_plugin, "poc.c")
        non_thread_func = ""
        fsrc = open(src, "r")
        fdst = open(dst, "w")

        devices_init_func_regx = ['initialize_vhci\(\);', 'initialize_netdevices_init\(\);', 'initialize_devlink_pci\(\);',
            'initialize_tun\(\);', 'initialize_netdevices\(\);', 'initialize_wifi_devices\(\);']
        
        syscalls = []
        if "386" in self.case['manager']:
            syscall_prefix = "__ia32_sys_"
        output = qemu.command(cmds="trace-cmd list -f | grep -E  \"^{}\"".format(syscall_prefix), user="root", wait=True)
        for line in output:
            if line.startswith(syscall_prefix):
                syscalls.append(line.strip())
        if len(syscalls) == 0:
            # try SyS_ prefix
            output = qemu.command(cmds="trace-cmd list -f | grep -E  \"^SyS_\"", user="root", wait=True)
            for line in output:
                if line.startswith("SyS_"):
                    syscalls.append(line.strip())
                    syscall_prefix = 'SyS_'
        common_entries.append(self._syscall_add_prefix(syscall_prefix, 'exit_group'))
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
            
            if 'hwsim80211_create_device' in line:
                self.addition_modules.append('mac80211_hwsim')
            
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
            
            if self._syscall_add_prefix(syscall_prefix, syscall) in syscalls: 
                syscall = self._syscall_add_prefix(syscall_prefix, syscall)
                group = [syscall]
                if syscall == self._syscall_add_prefix(syscall_prefix, 'recv'):
                    group = [self._syscall_add_prefix(syscall_prefix, 'recv'), self._syscall_add_prefix(syscall_prefix, 'recvfrom')]
                if syscall == self._syscall_add_prefix(syscall_prefix, 'send'):
                    group = [self._syscall_add_prefix(syscall_prefix, 'send'), self._syscall_add_prefix(syscall_prefix, 'sendto')]
                if syscall not in enabled_syscalls:
                    enabled_syscalls.extend(group)
            if syscall.startswith("syz_"):
                if syscall in self.syzcall2syscall:
                    for each in self.syzcall2syscall[syscall]:
                        enabled_syscalls.append(self._syscall_add_prefix(syscall_prefix, each))
                else:
                    self.logger.error("Cannot find {} in syzcall2syscall".format(syscall))
        return unique(enabled_syscalls)
    
    def _syscall_add_prefix(self, syscall_prefix, syscall):
        return syscall_prefix+syscall
    
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

    def cleanup(self):
        super().cleanup()
