import os, stat

from commands import Command
from deployer.deployer import Deployer
from subprocess import Popen, PIPE, STDOUT
from infra.tool_box import *

class EmptyCommand(Command):
    def __init__(self):
        super().__init__()
        self.args = None

    def add_arguments(self, parser):
        super().add_arguments(parser)
        parser.add_argument('--proj', nargs='?', action='store', 
                            help='Project name')

    def custom_subparser(self, parser, cmd):
        return parser.add_parser(cmd, help='Create an empty project')

    def run(self, args):
        self.args = args
        self.proj_dir = self.args.proj
        hash_val='123'
        cases = {}
        cases[hash_val]["commit"] = None
        cases[hash_val]["syzkaller"] = None
        cases[hash_val]["config"] = None
        cases[hash_val]["syz_repro"] = None
        cases[hash_val]["log"] = None
        cases[hash_val]["c_repro"] = None
        cases[hash_val]["time"] = None
        cases[hash_val]["manager"] = None
        cases[hash_val]["report"] =None
        cases[hash_val]["vul_offset"] = None
        cases[hash_val]["obj_size"] = None
        cases[hash_val]["kernel"] = None
        cases[hash_val]["hash_val"] = hash_val
        self.save_cases(cases, self.proj_dir)
        
    def save_cases(self, cases, name):
        cases_json_path = os.path.join(self.proj_dir, "cases.json")
        with open(cases_json_path, 'w') as f:
            json.dump(cases, f)
            f.close()
        self.logger.info("Created a new project {}".format(name))