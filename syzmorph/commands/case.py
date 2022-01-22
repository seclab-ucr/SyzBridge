import os, json, shutil

from commands import Command
from subprocess import Popen, PIPE, STDOUT, call
from dateutil import parser as time_parser
from infra.tool_box import *

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
        parser.add_argument('--hash', nargs='?', action='store', help='hash of a case or a file contains multiple hashs')
        parser.add_argument('--all', action='store_true', help='Get all case info')
        parser.add_argument('--completed', action='store_true', help='Get completed case info') 
        parser.add_argument('--incomplete', action='store_true', help='Get incomplete case info')
        parser.add_argument('--succeed', action='store_true', help='Get succeed case info')
        parser.add_argument('--error', action='store_true', help='Get error case info')
        parser.add_argument('--case-title', action='store_true', help='Get case title')
        parser.add_argument('--remove-stamp', action='append', default=[], help='Remove finish stamp')

        parser.add_argument('--prepare4debug', nargs='?', action='store', help='prepare a folder for case debug')

    def custom_subparser(self, parser, cmd):
        return parser.add_parser(cmd, help='Get cases information')

    def run(self, args):
        self.args = args
        self.proj_dir = os.path.join(os.getcwd(), "projects/{}".format(args.proj))
        self.cases = self.read_cases(args.proj)
        if args.hash != None:
            if os.path.exists(args.hash):
                t = self.cases.copy()
                self.cases = {}
                with open(args.hash, 'r') as f:
                    for hash_val in f.readlines():
                        hash_val = hash_val.strip()
                        self.cases[hash_val] = t[hash_val]
            else:
                self.cases = {args.hash: self.cases[args.hash]}
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
        if args.remove_stamp != []:
            for hash_val in self.cases:
                for stamp in args.remove_stamp:
                    for folder in ['succeed', 'error', 'incomplete', 'completed']:
                        stamp_path = os.path.join(self.proj_dir, folder, hash_val[:7], '.stamp', stamp)
                        if os.path.exists(stamp_path):
                            os.remove(stamp_path)
            print("Remove finish stamp {} from {} cases".format(args.remove_stamp, len(self.cases)))
        if args.prepare4debug != None:
            if args.hash == None:
                print('Please specify a case hash for debug')
                return
            self.prepare_case_for_debug(args.hash, args.prepare4debug)
    
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