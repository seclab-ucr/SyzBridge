import os, importlib
import multiprocessing

from commands import Command
from deployer.deployer import Deployer
from subprocess import Popen, PIPE, STDOUT
from infra.tool_box import *
from bs4 import BeautifulSoup

class FuzzCommand(Command):
    def __init__(self):
        super().__init__()
        self.args = None
        self.dummy_case_hash = None
        self.proj_dir = None
        self.cases = {}
        self.logger = init_logger(__name__, handler_type=STREAM_HANDLER)

    def add_arguments(self, parser):
        super().add_arguments(parser)
        parser.add_argument('--config', nargs='?', action='store',
                            help='config file. Will be overwritten by arguments if conflict.')
        parser.add_argument('--proj', nargs='?', action='store',
                            help='project name')
        parser.add_argument('--server', nargs='?', action='store',
                            help='remote sever')
        parser.add_argument('--port', nargs='?', action='store',
                            help='remote sever port')
        parser.add_argument('--prog-arch', nargs='?', action='store',
                            help='[32|64], indicates the architecture of the program')
        parser.add_argument('--linux', nargs='?', action='store',
                            help='Linux repo index specified')
        # Task
        self.add_arguments_for_plugins(parser)

    def custom_subparser(self, parser, cmd):
        return parser.add_parser(cmd, help='Fuzz for new crashes')
    
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
                self.logger.error("Fail to load plugin {}: {}".format(module_name, e))
                continue

    def read_cases(self, name):
        cases = {}
        work_path = os.getcwd()
        cases_json_path = os.path.join(work_path, "projects/{}/cases.json".format(name))
        if os.path.exists(cases_json_path):
            with open(cases_json_path, 'r') as f:
                cases = json.load(f)
                f.close()
        else:
            self.logger.info("No proj {} found".format(name))
            return None
        return cases

    def build_work_dir(self):
        os.makedirs(os.path.join(self.proj_dir, "incomplete"), exist_ok=True)
        os.makedirs(os.path.join(self.proj_dir, "completed"), exist_ok=True)
        os.makedirs(os.path.join(self.proj_dir, "succeed"), exist_ok=True)
        os.makedirs(os.path.join(self.proj_dir, "error"), exist_ok=True)

    def run(self, args):
        self.args = args
        if args.proj == None or args.prog_arch == None:
            self.logger.error("Please specify a project or program architecture")
            return
        self.args.console = False
        self.args.parallel_max = 1
        self.proj_dir = os.path.join(os.getcwd(), "projects/{}".format(args.proj))
        self.build_work_dir()
        self.scan_remote_crashes()
        index = 0
        if self.args.linux != None:
            index = int(self.args.linux)
        for crash_hash in self.cases:
            self.deploy_one_case(index, crash_hash)
    
    def scan_remote_crashes(self):
        url = "http://{}:{}/".format(self.args.server, self.args.port)
        req = request_get(url)
        soup = BeautifulSoup(req.text, "html.parser")
        kernel = soup.find_all('li')
        for each_kernel in kernel:
            url = "http://{}:{}/{}".format(self.args.server, self.args.port, each_kernel.text.strip('\\'))
            req = request_get(url)
            soup_crash = BeautifulSoup(req.text, "html.parser")
            crashes = soup_crash.find_all('li')
            for each in crashes:
                hash_val = each.text.strip('\\')
                self.cases[hash_val] = {}
                detail = self.get_crash_detail(url, hash_val)
                self.cases[hash_val] = detail
        return

    def get_crash_detail(self, url, hash_val):
        detail = {"hash": hash_val, "kernel": "upstream"}
        if self.args.prog_arch == "32":
            detail['manager'] = 'qemu-i386'
        if self.args.prog_arch == "64":
            detail['manager'] = 'qemu-64'
        new_url = "{}/{}".format(url, hash_val)
        req = request_get(new_url)
        soup = BeautifulSoup(req.text, "html.parser")
        files = soup.find_all('li')
        for each in files:
            if each.text == "description":
                t = request_get("{}/{}".format(new_url, each.text))
                detail["title"] = t.text
            if 'log' not in detail and (regx_match("log\d+", each.text) or regx_match("repro.log", each.text)):
                detail["log"] = "{}/{}".format(new_url, each.text)
            if 'report' not in detail and (regx_match("report\d+", each.text) or regx_match("repro.report", each.text)):
                detail["report"] = "{}/{}".format(new_url, each.text)
            if regx_match("commit", each.text):
                t = request_get("{}/{}".format(new_url, each.text))
                detail["commit"] = t.text
            if regx_match("syzkaller", each.text):
                t = request_get("{}/{}".format(new_url, each.text))
                detail["syzkaller"] = t.text
            if regx_match(".config", each.text):
                detail["config"] = "{}/{}".format(new_url, each.text)
            if regx_match("repro.prog", each.text):
                detail["syz_repro"] = "{}/{}".format(new_url, each.text)
            if regx_match("repro.cprog", each.text):
                detail["c_repro"] = "{}/{}".format(new_url, each.text)
            if regx_match("info.txt", each.text):
                t = request_get("{}/{}".format(new_url, each.text))
                for line in t.text.split('\n'):
                    if regx_match(r'date: (.*)', line):
                        detail["time"] = regx_get(r'date: (.*)', line, 0)
                    if regx_match(r'commit kernel: (.*)', line):
                        detail["commit"] = regx_get(r'commit kernel: (.*)', line, 0)
                    if regx_match(r'commit syzkaller: (.*)', line):
                        detail["syzkaller"] = regx_get(r'commit syzkaller: (.*)', line, 0)
        if 'c_repro' not in detail:
            detail['c_repro'] = None

        return detail
    
    def parse_config(self, config):
        from expbridge.infra.config.config import Config
        
        cfg = Config()
        cfg.load_from_file(config)

        return cfg
    
    def deploy_one_case(self, index, hash_val):
        case = self.cases[hash_val]
        if 'syz_repro' not in case:
            self.logger.info("{} has no syz repro".format(hash_val))
            return
        dp = Deployer(owner=self, index=index, case_hash=hash_val, case=case)
        dp.deploy()
        self.logger.info("{} exit".format(hash_val))
        del dp