import os, json

from commands import Command
from subprocess import call

from infra.tool_box import regx_get
from infra.strings import case_hash_syzbot_regx

class CaseCommand(Command):
    def __init__(self):
        super().__init__()
        self.args = None
        self.cases = {}

    def add_arguments(self, parser):
        super().add_arguments(parser)
        parser.add_argument('--proj', nargs='?', action='store', help='project name')
        parser.add_argument('--all', action='store_true', help='Get all case info')
        parser.add_argument('--completed', action='store_true', help='Get completed case info') 
        parser.add_argument('--incomplete', action='store_true', help='Get incomplete case info')
        parser.add_argument('--succeed', action='store_true', help='Get succeed case info')
        parser.add_argument('--error', action='store_true', help='Get error case info')
        parser.add_argument('--case-title', action='store_true', help='Get case title')

    def custom_subparser(self, parser, cmd):
        return parser.add_parser(cmd, help='Get cases information')

    def run(self, args):
        self.args = args
        self.proj_dir = os.path.join(os.getcwd(), "projects/{}".format(args.proj))
        self.cases = self.read_cases(args.proj)
        if args.all:
            self.print_case_info()
        if args.completed:
            show = self.read_case_from_folder('completed')
            self.print_case_info(show)
        if args.incomplete:
            show = self.read_case_from_folder('incomplete')
            self.print_case_info(show)
        if args.succeed:
            show = self.read_case_from_folder('succeed')
            self.print_case_info(show)
        if args.error:
            show = self.read_case_from_folder('error')
            self.print_case_info(show)

    def read_case_from_folder(self, folder):
        res = []
        folder_path = os.path.join(self.proj_dir, folder)
        for case in os.listdir(folder_path):
            log_path = os.path.join(folder_path, case, 'log')
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