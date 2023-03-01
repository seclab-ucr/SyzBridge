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

    def add_arguments(self, parser):
        super().add_arguments(parser)
        parser.add_argument('--fuzzing-workdir', nargs='?', action='store', 
                            help='Path of syzkaller workdir')
        parser.add_argument('--config', nargs='?', action='store',
                            help='config file. Will be overwritten by arguments if conflict.')
        parser.add_argument('--proj', nargs='?', action='store',
                            help='project name')
        parser.add_argument('--server', nargs='?', action='store',
                            help='remote sever')
        parser.add_argument('--port', nargs='?', action='store',
                            help='remote sever port')
        # Task
        self.add_arguments_for_plugins(parser)

    def custom_subparser(self, parser, cmd):
        return parser.add_parser(cmd, help='Fuzz for new crashes')
    
    def add_arguments_for_plugins(self, parser):
        proj_dir = os.path.join(os.getcwd(), "syzmorph")
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

    def run(self, args):
        self.args = args
        self.proj_dir = os.path.join(os.getcwd(), "projects/{}".format(args.proj))
        self.scan_remote_crashes()
    
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
        new_url = "{}/{}".format(url, hash_val)
        req = request_get(new_url)
        soup = BeautifulSoup(req.text, "html.parser")
        files = soup.find_all('li')
        for each in files:
            if each.text == "description":
                t = request_get("{}/{}".format(new_url, each.text))
                detail["title"] = t.text
            if regx_match("log\d+", each.text):
                detail["log"] = "{}/{}".format(new_url, each.text)
            if regx_match("report\d+", each.text):
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
                detail["c_prog"] = "{}/{}".format(new_url, each.text)
            if regx_match("info.txt", each.text):
                t = request_get("{}/{}".format(new_url, each.text))
                for line in t.text.split('\n'):
                    if regx_match(r'date: (.*)', line):
                        detail["time"] = regx_get(r'date: (.*)', line, 0)
                    if regx_match(r'commit kernel: (.*)', line):
                        detail["commit"] = regx_get(r'commit kernel: (.*)', line, 0)
                    if regx_match(r'commit syzkaller: (.*)', line):
                        detail["syzkaller"] = regx_get(r'commit syzkaller: (.*)', line, 0)

        return detail
    
    def parse_config(self, config):
        from syzmorph.infra.config.config import Config
        
        cfg = Config()
        cfg.load_from_file(config)

        return cfg
    
    def deploy_one_case(self, index, hash_val):
        case = self.cases[hash_val]
        dp = Deployer(owner=self, index=index, case_hash=hash_val, case=case)
        dp.deploy()
        self.logger.info("{} exit".format(hash_val))
        del dp