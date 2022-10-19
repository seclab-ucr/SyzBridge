import os, json, shutil
import time

from commands import Command
from infra.config.config import Config
from modules.vm import VM
from infra.tool_box import *
from infra.strings import case_hash_syzbot_regx

class CaseCommand(Command):
    def __init__(self):
        super().__init__()
        self.args = None
        self.cases = {}

    def add_arguments(self, parser):
        super().add_arguments(parser)
        parser.add_argument('--proj', nargs='?', action='store', help='project name')
        parser.add_argument('--case', nargs='?', action='store', help='hash of a case or a file contains multiple hashs')
        parser.add_argument('--all', action='store_true', help='Get all case info')
        parser.add_argument('--count', '-c', action='store_true', help='count the number of bugs')

        parser.add_argument('--completed', action='store_true', help='Get completed case info') 
        parser.add_argument('--incomplete', action='store_true', help='Get incomplete case info')
        parser.add_argument('--succeed', action='store_true', help='Get succeed case info')
        parser.add_argument('--error', action='store_true', help='Get error case info')
        parser.add_argument('--case-title', action='store_true', help='Get case title')
        parser.add_argument('--remove-stamp', action='append', default=[], help='Remove finish stamp')
        parser.add_argument('--show', action='store_true', help='Show case info')

        parser.add_argument('--config', nargs='?', action='store', help='config file of a project')
        parser.add_argument('--launch-qemu', nargs='?', action='store', help='launch qemu of specified distro')
        parser.add_argument('--qemu-ssh', nargs='?', action='store', help='overwrite the default ssh port')
        parser.add_argument('--get-trace', action='store_true', help='Get a ftrace from original PoC')
        parser.add_argument('--enable-module', action='append', default=[], help='enable additional modules before getting trace')
        parser.add_argument('--parse-trace', nargs='?', action='store', help='Parse a ftrace. The vaule could be a ftrace file or a distro name')

        parser.add_argument('--prepare4debug', nargs='?', action='store', help='prepare a folder for case debug')

    def custom_subparser(self, parser, cmd):
        return parser.add_parser(cmd, help='Get cases information')

    def run(self, args):
        self.args = args
        self.proj_dir = os.path.join(os.getcwd(), "projects/{}".format(args.proj))
        self.cases = self.read_cases(args.proj)
        if args.case != None:
            if os.path.exists(args.case):
                t = self.cases.copy()
                self.cases = {}
                with open(args.case, 'r') as f:
                    for hash_val in f.readlines():
                        hash_val = hash_val.strip()
                        self.cases[hash_val] = t[hash_val]
            else:
                if args.case not in self.cases:
                    print("{} is not in project {}".format(args.case, args.proj))
                    return
                self.cases = {args.case: self.cases[args.case]}
        if args.count:
            j = json.load(open(self.proj_dir + '/cases.json', 'r'))
            print(len(j))
            return
        
        if args.config != None:
            self.cfg = Config()
            self.cfg.load_from_file(args.config)

        if args.launch_qemu != None:
            self.launch_qemu(args.launch_qemu)
            return
        if args.parse_trace != None:
            self.parse_trace(args.parse_trace)
            return
        if args.show:
            for hash_val in self.cases:
                print(json.dumps(self.cases[hash_val], indent=4))
        work_folder = []
        if args.all:
            work_folder = ['succeed', 'error', 'incomplete', 'completed']
            self.print_case_info()
        if args.completed:
            work_folder.append('completed')
            show = self.read_case_from_folder('completed')
            self.print_case_info(show)
        if args.incomplete:
            work_folder.append('incomplete')
            show = self.read_case_from_folder('incomplete')
            self.print_case_info(show)
        if args.succeed:
            work_folder.append('succeed')
            show = self.read_case_from_folder('succeed')
            self.print_case_info(show)
        if args.error:
            work_folder.append('error')
            show = self.read_case_from_folder('error')
            self.print_case_info(show)
        if args.remove_stamp != []:
            for hash_val in self.cases:
                for stamp in args.remove_stamp:
                    for folder in work_folder:
                        stamp_path = os.path.join(self.proj_dir, folder, hash_val[:7], '.stamp', stamp)
                        if os.path.exists(stamp_path):
                            os.remove(stamp_path)
            print("Remove finish stamp {} from {} cases".format(args.remove_stamp, len(self.cases)))
        if args.prepare4debug != None:
            if args.case == None:
                print('Please specify a case hash for debug')
                return
            self.prepare_case_for_debug(args.case, args.prepare4debug)
    
    def prepare_case_for_debug(self, hash_val, folder):
        case_debug_path = folder
        if not os.path.isdir(case_debug_path):
            print("Cannot find directory {}".format(case_debug_path))
            return
        case = self.cases[hash_val]
        self.path_debug = os.path.join(case_debug_path, hash_val[:7])
        try:
            os.mkdir(self.path_debug)
        except Exception as e:
            print("Cannot create directory {}".format(self.path_debug))
            print(e)
            return
        linux_repo = os.path.join(self.proj_dir, 'tools', 'linux-{}-0'.format(case['kernel']))
        if not os.path.exists(linux_repo):
            print("Cannot find linux repo {}. Run analysis on this case will automatically create a linux repo.".format(linux_repo))
            return
        shutil.copytree(linux_repo, os.path.join(self.path_debug, 'linux'))
        os.mkdir(os.path.join(self.path_debug, 'exp'))
        call(['curl', case['c_repro'], '>' , os.path.join(self.path_debug, 'exp', 'poc.c')])
        call(['curl', case['config'], '>' , os.path.join(self.path_debug, 'linux', '.config')])
        call(['make', '-j`nproc`'])

    def read_case_from_folder(self, folder):
        res = []
        folder_path = os.path.join(self.proj_dir, folder)
        for case in os.listdir(folder_path):
            log_path = os.path.join(folder_path, case, 'log')
            if os.path.exists(log_path):
                with open(log_path, 'r') as f:
                    line = f.readline()
                    hash_val = regx_get(case_hash_syzbot_regx, line, 0)
                    res.append(hash_val)
                    f.close()
        return res
    
    def read_cases(self, name):
        cases = {}
        work_path = os.getcwd()
        cases_json_path = os.path.join(work_path, "projects/{}/cases.json".format(name))
        if os.path.exists(cases_json_path):
            with open(cases_json_path, 'r') as f:
                cases = json.load(f)
                f.close()
        return cases
    
    def print_case_info(self, show=[]):
        for hash_val in self.cases:
            if hash_val in show or show == []:
                line = hash_val
                if self.args.case_title:
                    line += ' | ' + self.cases[hash_val]['title']
                print(line)
            
    def parse_trace(self, value):
        if os.path.exists(value):
            self._call_ftraceparser(value)
        else:
            if self.args.config == None:
                print("If --parse-trace followed by distro name, you need to specify a config file")
                return
            if self.args.case == None:
                print("If --parse-trace followed by distro name, you need to specify a case hash")
                return
            if self.args.proj == None:
                print("If --parse-trace followed by distro name, you need to specify a project")
                return
            if value == "upstream":
                distro = self.cfg.get_upstream()
            else:
                distro = self.cfg.get_distro_by_name(value)
                if distro == None:
                    print('Cannot find distro {}'.format(value))
                    return

            folder = self._get_case_folder(self.args.case)
            trace_analysis_path = os.path.join(self.proj_dir, folder, self.args.case[:7], 'TraceAnalysis')
            ftrace_file = os.path.join(trace_analysis_path, 'trace-{}.report'.format(distro.distro_name))
            if not os.path.exists(ftrace_file):
                print("Cannot find ftrace file {}".format(ftrace_file))
                return
            self._call_ftraceparser(ftrace_file)
        return
    
    def launch_qemu(self, distro_name):
        from rich.table import Table
        from rich.align import Align
        from rich.console import Console
        from rich.live import Live
        from rich import box
        from rich.text import Text
        from rich.spinner import Spinner

        console = Console()
        if self.args.case is None:
            print('Please specify a case hash')
            return
        if self.args.config is None:
            print('Please specify a config file')
            return

        folder = self._get_case_folder(self.args.case)

        distro = self.cfg.get_distro_by_name(distro_name)
        if distro == None:
            print('Cannot find distro {}'.format(distro_name))
            return

        case_path = os.path.join(self.proj_dir, folder, self.args.case[:7])
        launch_script_path = os.path.join(case_path, 'BugReproduce', 'launch_{}.sh'.format(distro_name))
        if not os.path.exists(launch_script_path):
            print("Cannot find launch script {}".format(launch_script_path))
            return
        cmd = None
        with open(launch_script_path, 'r') as f:
            line = f.readline()
            f.close()
            if self.args.qemu_ssh != None:
                ssh_text = regx_get(r'(hostfwd=tcp::\d+-:22)', line, 0)
                if ssh_text == None:
                    print("Cannot find ssh port in launch script")
                    return
                line = line.replace(ssh_text, 'hostfwd=tcp::{}-:22'.format(self.args.qemu_ssh))
            line = line.replace('incomplete', folder)
            cmd = line
        if cmd == None:
            console.print("Open launch script error")
            return
        distro_image = regx_get(r'file=(.*-snapshot.img)', cmd, 0)
        ssh_port = regx_get(r'hostfwd=tcp::(\d+)-:22', cmd, 0)
        mod_anly_res = self._get_results("ModulesAnalysis", case_path)
        mod_anly_text = ""
        for module in mod_anly_res:
            if distro_name in mod_anly_res[module]['missing']:
                if mod_anly_res[module]['missing'][distro_name]['missing_reason'] != "Module disabled":
                    mod_anly_text += module + " "
        
        cap_chk_res = self._get_results("CapabilityCheck", case_path)
        cap_chk_text = ""
        for cap in cap_chk_res:
            cap_text = regx_get(r'(.*)-\d+', cap, 0)
            cap_chk_text += cap_text + " "

        mem = regx_get(r'-m (\d+G)', cmd, 0)
        cpu = regx_get(r'-smp (\d+)', cmd, 0)
        vm = VM(linux=None, kernel=distro, hash_tag="qemu {}".format(distro.distro_name), debug=False,
            port=ssh_port, key=distro.ssh_key, image=distro_image, mem=mem, cpu=cpu)
        if self.args.get_trace:
            vm.run(alternative_func=self._get_trace, args=(case_path,distro_name,))
        else:
            vm.run()
        
        out_begin = 0
        out_end = 0
        with Live(console=console) as live_table:
            try:
                while vm.instance.poll() == None or out_begin < len(vm.output):
                    out_end = len(vm.output)
                    if out_begin < out_end:
                        print("\n".join(vm.output[out_begin:]))
                    table = Table(box=box.ROUNDED, expand=True, show_lines=True)
                    if out_end == 0:
                        table.add_row("", Spinner('dots', text=Text('Wating for kernel to boot...', style="green")))
                    table.add_row("Distro name", Text(distro_name,style="green",overflow="fold"))
                    table.add_row("Distro image", Text(distro_image,style="green",overflow="fold"))
                    table.add_row("Distro ssh port", Text(ssh_port,style="green",overflow="fold"))
                    table.add_row("Distro ssh key", Text(distro.ssh_key,style="green",overflow="fold"))
                    table.add_row("VM log", Text("/tmp/vm.log",style="green",overflow="fold"))
                    table.add_row("Missing modules", Text(mod_anly_text,style="red",overflow="fold"))
                    table.add_row("Required capabilities", Text(cap_chk_text,style="red",overflow="fold"))

                    live_table.update(Align.center(table))
                    out_begin = out_end
            except KeyboardInterrupt:
                vm.kill()
                vm.instance.wait()
                return
        ret = vm.wait()
        if self.args.get_trace and ret:
            console.print("Downloaded trace to /tmp/trace-{}.report".format(distro_name))
        return
    
    def _get_case_folder(self, case_hash):
        folder = None
        hash_vals = self.read_case_from_folder('completed')
        if case_hash in hash_vals:
            folder = 'completed'
        hash_vals = self.read_case_from_folder('incomplete')
        if case_hash in hash_vals:
            folder = 'incomplete'
        hash_vals = self.read_case_from_folder('succeed')
        if case_hash in hash_vals:
            folder = 'succeed'
        hash_vals = self.read_case_from_folder('error')
        if case_hash in hash_vals:
            folder = 'error'
        return folder
    
    def _call_ftraceparser(self, trace_path):
        ftraceparser_path = os.path.join(os.getcwd(), 'syzmorph/infra/ftraceparser/')
        run_cmd = ['python3', 'ftraceparser', trace_path]
        call(run_cmd, shell=False, cwd=ftraceparser_path, env=os.environ.copy())

    def _get_results(self, module_name, case_path):
        results_path = os.path.join(case_path, module_name, 'results.json')
        if not os.path.exists(results_path):
            return {}
        r = json.load(open(results_path, 'r'))
        return r
    
    def _get_trace(self, qemu, case_path, distro_name):
        case_plugin_path = os.path.join(case_path, 'TraceAnalysis')
        poc_src = "poc.c"
        poc_path = os.path.join(case_plugin_path, poc_src)
        qemu.upload(user="root", src=[poc_path], dst="/root", wait=True)
        qemu.output.append("uploading {} to /root".format(poc_src))
        if '386' in self.cases[self.args.case]['manager']:
            out = qemu.command(cmds="gcc -m32 -pthread -o poc {}".format(poc_src), user="root", wait=True)
            qemu.output.append("gcc -m32 -pthread -o poc {}".format(poc_src))
            qemu.output.extend(out)
        else:
            out = qemu.command(cmds="gcc -pthread -o poc {}".format(poc_src), user="root", wait=True)
            qemu.output.append("gcc -pthread -o poc {}".format(poc_src))
            qemu.output.extend(out)
        trace_filename = "trace-{}".format(distro_name)
        trace_poc_script_name = 'trace-poc-{}-trace.sh'.format(distro_name)
        trace_poc_path = os.path.join(case_path, 'TraceAnalysis', trace_poc_script_name)

        if self.args.enable_module != []:
            for module in self.args.enable_module:
                out = qemu.command(cmds="modprobe {}".format(module), user="root", wait=True)
                qemu.output.append("modprobe {}".format(module))
                qemu.output.extend(out)

        qemu.upload(user="root", src=[trace_poc_path], dst="/root", wait=True)
        qemu.output.append("uploading {} to /root".format(trace_poc_path))

        out = qemu.command(cmds="chmod +x {0} && ./{0}\n".format(trace_poc_script_name), user="root", wait=True)
        qemu.output.append("chmod +x {0} && ./{0}\n".format(trace_poc_script_name))
        qemu.output.extend(out)

        out = qemu.command(cmds="trace-cmd report > trace.report", user="root", wait=True)
        qemu.output.append("trace-cmd report > trace.report")
        qemu.output.extend(out)

        qemu.download(user="root", src=["/root/trace.report"], dst="/tmp/{}.report".format(trace_filename), wait=True)
        qemu.output.append("downloading /root/trace.report to /tmp/{}.report".format(trace_filename))
        if qemu.dumped_ftrace:
            self.logger.info("Ftrace dumped, discarded.")
        return True