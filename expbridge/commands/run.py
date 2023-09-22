import multiprocessing, threading
import os, importlib
import json, gc, time

from commands import Command
from infra.error import *
from infra.tool_box import STREAM_HANDLER, init_logger, get_terminal_width
from deployer.deployer import Deployer

from queue import Empty
from subprocess import call
class RunCommand(Command):
    def __init__(self):
        super().__init__()
        self.lock = threading.Lock()
        self.queue = multiprocessing.Queue()
        self.rest = 0
        self.total = 0
        self.cases = None
        self.proj_dir = None
        self.cfg = None
        self.console_queue = None
        self._module_folder = None
        self.logger = init_logger(__name__, handler_type=STREAM_HANDLER)
        
    def add_arguments(self, parser):
        super().add_arguments(parser)

        # Mandatory
        parser.add_argument('--proj', nargs='?', action='store',
                            help='project name')
        parser.add_argument('--case', nargs='?', action='store',
                            help='case hash (If only run one case of the project')
        parser.add_argument('--config', nargs='?', action='store',
                            help='config file. Will be overwritten by arguments if conflict.')
        # Task
        self.add_arguments_for_plugins(parser)

        # Regular arguments
        parser.add_argument('--image', nargs=1, action='store',
                            help='Linux image for bug reproducing')
        parser.add_argument('--distro', nargs='?', action='store',
                            help='Specifying the distro')
        parser.add_argument('-pm', '--parallel-max', nargs='?', action='store',
                            default='1', help='The maximum of parallel processes\n'
                                            '(default valus is 1)')
        parser.add_argument('--ssh-port', nargs='?', action='store',
                            help='The default port of ssh using by QEMU\n'
                            '(default port is 36777)')
        parser.add_argument('--ssh-key', nargs=1, action='store',
                            help='The private key for ssh connection')
        parser.add_argument('--linux', nargs='?', action='store',
                            help='Linux repo index specified')
        parser.add_argument('--console', action='store_true',
                            help='Enable console mode')
    
    def add_arguments_for_plugins(self, parser):
        proj_dir = os.path.join(os.getcwd(), "expbridge")
        modules_dir = os.path.join(proj_dir, "plugins")
        self._module_folder = [ cmd for cmd in os.listdir(modules_dir)
                    if not cmd.endswith('.py') and not cmd == "__pycache__" ]
        for module_name in self._module_folder:
            try:
                module = importlib.import_module("plugins.{}".format(module_name))
                enable = module.ENABLE
                if not enable:
                    continue
                help_msg = module.DESCRIPTION
                t = module_name.split('_')
                cmd_msg = '--' + '-'.join(t)
                parser.add_argument(cmd_msg, action='store_true', help=help_msg)
            except Exception as e:
                print("Fail to load plugin {}: {}".format(module_name, e))
                continue

    def custom_subparser(self, parser, cmd):
        return parser.add_parser(cmd, help='Run bug reproduce process or bug analysis')

    def read_cases(self, name):
        cases = {}
        work_path = os.getcwd()
        cases_json_path = os.path.join(work_path, "projects/{}/cases.json".format(name))
        if os.path.exists(cases_json_path):
            with open(cases_json_path, 'r') as f:
                cases = json.load(f)
                f.close()
        else:
            print("No proj {} found".format(name))
            return None
        return cases

    def deploy_one_case(self, index, hash_val):
        case = self.cases[hash_val]
        dp = Deployer(owner=self, index=index, case_hash=hash_val, case=case)
        dp.deploy()
        self.logger.info("{} exit".format(hash_val))
        del dp

    def prepare_cases(self, index,):
        while(1):
            self.lock.acquire(blocking=True)
            try:
                hash_val = self.queue.get(block=True, timeout=3)
                self.logger.info("Thread {}: run case {} [{}/{}] left".format(index, hash_val, self.rest.value-1, self.total))
                self.rest.value -= 1
                self.lock.release()
                x = multiprocessing.Process(target=self.deploy_one_case, args=(index, hash_val,), name="lord-{}".format(index))
                x.start()
                x.join()
                gc.collect()
            except Empty:
                self.lock.release()
                break
        self.logger.info("Thread {} exit->".format(index))

    def parse_config(self, config):
        from expbridge.infra.config.config import Config
        
        cfg = Config()
        cfg.load_from_file(config)

        return cfg

    def check_essential_args(self):
        if self.args.proj == None:
            self.logger.error("--proj must be specified.")
            return True
        if self.args.config == None and \
                (self.args.image == None or self.args.ssh_key == None):
            self.logger.error("--image or --ssh-key must be specified or pass --config to import them from a config file.")
            return True
        return False

    def print_args_info(self):
        if self.args.console:
            from rich.table import Table
            term_width = get_terminal_width()

            enabled_modules = []
            for module_name in self._module_folder:
                try:
                    if getattr(self.args, module_name):
                        enabled_modules.append(module_name)
                except AttributeError:
                    pass
            enabled_modules_text = ' | '.join(enabled_modules)

            msg = (
                "\n┌─[ Running with the following parameters ]\n"
                + f"├"
                + "─" * (term_width - 1)
                + "\n"
                + f"│\tProj : [sky_blue3]{self.args.proj}[/sky_blue3]\n"
                + f"│\tEnabled Plugins : [yellow]{enabled_modules_text}[/yellow]\n"
                + f"│\tParallel Processes : [red]{self.args.parallel_max}[/red]\n"
                + f"│\tConfig File : [dark_sea_green1]{self.args.config}[/dark_sea_green1]\n"
                + "└" + "─" * (term_width - 1)
            )

            self.console.console.print(msg)

            table = Table(title="Testing Kernels", title_style="bold", header_style="bold magenta", border_style="navy_blue", expand=True)
            table.add_column("Distro Name", justify="center")
            table.add_column("Distro Image", justify="center")
            table.add_column("Distro Source", justify="center")
            table.add_column("SSH Port", justify="center")
            table.add_column("SSH Key", justify="center")
            if self.cfg != None:
                for vendor in self.cfg.kernel.__dict__:
                    t = getattr(self.cfg.kernel, vendor)
                    table.add_row(
                        str(t.distro_name), str(t.distro_image), str(t.distro_src), str(t.ssh_port), str(t.ssh_key)
                    )

            self.console.console.print(table)
            return
        else:
            print("[*] proj: {}".format(self.args.proj))
            if self.cfg != None:
                for vendor in self.cfg.kernel.__dict__:
                    t = getattr(self.cfg.kernel, vendor)
                    print("=========={}==========".format(t.distro_name))
                    print("[*] vendor image: {}".format(t.distro_image))
                    print("[*] ssh_port: {}".format(t.ssh_port))
                    print("[*] ssh_key: {}".format(t.ssh_key))
                    print("[*] distro_src: {}".format(t.distro_src))
                    print("[*] distro_name: {}".format(t.distro_name))
    
    def build_work_dir(self):
        os.makedirs(os.path.join(self.proj_dir, "incomplete"), exist_ok=True)
        os.makedirs(os.path.join(self.proj_dir, "completed"), exist_ok=True)
        os.makedirs(os.path.join(self.proj_dir, "succeed"), exist_ok=True)
        os.makedirs(os.path.join(self.proj_dir, "error"), exist_ok=True)
    
    def run_console(self):
        self.console.run()
    
    def run(self, args):
        self.args = args
        if self.check_essential_args():
            return

        try:
            if self.args.config != None:
                self.cfg = self.parse_config(self.args.config)
        except TargetFileNotExist as e:
            self.logger.error(e)
            return
        except ParseConfigError as e:
            self.logger.error(e)
            return
        except TargetFormatNotMatch as e:
            self.logger.error(e)
            return

        if self.args.console:
            from infra.console import CoolConsole

            self.console_queue = multiprocessing.Queue()
            self.console = CoolConsole("ExpBridge", self.args.parallel_max, self.console_queue)
        self.print_args_info()

        if self.args.console:
            threading.Thread(target=self.run_console, name="console").start()
        
        self.proj_dir = os.path.join(os.getcwd(), "projects/{}".format(args.proj))

        self.cases = self.read_cases(args.proj)
        if args.case != None:
            if os.path.exists(args.case):
                t = {}
                for line in open(args.case, 'r').readlines():
                    t[line.strip()] = self.cases[line.strip()]
                self.cases = t
            else:
                self.cases = {args.case: self.cases[args.case]}
        if self.args.distro != None:
            for hash_val in self.cases:
                self.cases[hash_val]['affect'] = self.args.distro
        self.build_work_dir()

        for key in self.cases:
            self.queue.put(key)
        
        parallel_max = int(self.args.parallel_max)
        l = list(self.cases.keys())
        self.total = len(l)
        self.rest = multiprocessing.Value('i', self.total)
        for i in range(0,min(parallel_max,self.total)):
            if self.args.linux != None:
                index = int(self.args.linux)
            else:
                index = i
            x = threading.Thread(target=self.prepare_cases, args=(index,), name="dispatcher-{}".format(i))
            x.start()
            time.sleep(1)