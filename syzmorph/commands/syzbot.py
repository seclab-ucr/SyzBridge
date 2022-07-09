import os, json

from commands import Command
from infra.error import *
from infra.tool_box import STREAM_HANDLER, init_logger

class SyzbotCommand(Command):
    def __init__(self):
        super().__init__()
        self.proj_dir = None
        self.cfg = None
        self.logger = init_logger(__name__, handler_type=STREAM_HANDLER)

    def add_arguments(self, parser):
        super().add_arguments(parser)
        parser.add_argument('--get',  nargs='?', action='store',
                            help='[string] To get a case by hash or a file contains multiple hashs.')
        parser.add_argument('--proj',  nargs='?', action='store',
                            help='[string] To save the cases into a project')
        parser.add_argument('--url', nargs='?', action='store',
                            default="https://syzkaller.appspot.com/upstream",
                            help='[string] Indicate an URL for automatically crawling and running.\n'
                                '(default value is \'https://syzkaller.appspot.com/upstream\')')
        parser.add_argument('--key', action='append', default=[],
                            help='[list] The keywords for detecting cases.\n'
                                '(By default, it retrieve all cases)\n'
                                'This argument could be multiple values')
        parser.add_argument('--max-retrieval', nargs='?', action='store',
                            default='9999',
                            help='[string] The maximum of cases for retrieval\n'
                                '(By default all the cases will be retrieved)')
        parser.add_argument('--config', nargs='?', action='store',
                            help='config file. Will be overwritten by arguments if conflict.')
        parser.add_argument('--filter-by-reported', nargs='?',
                            default='',
                            help='[string] filter by bug reported days (X1-X2 days)\n')
        parser.add_argument('--filter-by-closed', nargs='?',
                            default='',
                            help='[string] filter by bug closed days (X1-X2 days) \n')
        parser.add_argument('--filter-by-kernel', action='append', default=[],
                            help='[list] filter by targeting kernel.\n\
                            e.g., --filter-by-kernel=upstream --filter-by-kernel=linux-next')
        parser.add_argument('--filter-by-c-prog', action='store_true',
                            help='[bool] filter bugs that do not have a c reproducer\n')
        parser.add_argument('--filter-by-fixes-tag', action='store_true',
                            help='[bool] filter bugs that do not have fixes tag\n')
        parser.add_argument('--addition', action='store_true',
                            help='[bool] add additional cases\n')
    
    def custom_subparser(self, parser, cmd):
        return parser.add_parser(cmd, help='Get a case by hash or a file contains multiple hashs.')
    
    def parse_config(self, config):
        from syzmorph.infra.config.config import Config
        
        cfg = Config()
        cfg.load_from_file(config)

        return cfg

    def run(self, args):
        self.args = args
        if self.check_essential_args():
            return
        
        self.print_args_info()

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

        if self.args.key == None:
            self.args.key = ['']
        
        self.proj_dir = self.build_proj_dir(args.proj)
        if self.proj_dir == None:
            return

        from syzmorph.modules.syzbot import Crawler

        crawler = Crawler(url=self.args.url, keyword=self.args.key, max_retrieve=int(self.args.max_retrieval), 
            filter_by_reported=self.args.filter_by_reported, filter_by_closed=self.args.filter_by_closed, 
            filter_by_c_prog=self.args.filter_by_c_prog, filter_by_kernel=self.args.filter_by_kernel,
            filter_by_fixes_tag=self.args.filter_by_fixes_tag,
            cfg=self.cfg, debug=self.args.debug, log_path = self.proj_dir)
        
        try:
            if self.args.get != None:
                if len(self.args.get) == 40:
                    crawler.run_one_case(self.args.get)
                else:
                    with open(self.args.get, 'r') as f:
                        text = f.readlines()
                        for line in text:
                            line = line.strip('\n')
                            crawler.run_one_case(line)
            else:
                crawler.run()
        except:
            self.logger.error("Something went wrong in crawler, check the log for more details.")

        if self.args.addition:
            self.cases = self.read_cases(args.proj)
            for e in crawler.cases:
                if e not in self.cases:
                    self.cases[e] = crawler.cases[e]
        else:
            self.cases = crawler.cases
        self.logger.info("Cases info saved in {}".format(os.path.join(self.proj_dir, "cases.json")))
        self.save_cases(crawler.cases, args.proj) 
    
    def check_essential_args(self):
        if self.args.proj == None:
            self.logger.error("--proj must be specified.")
            return True
        return False

    def build_proj_dir(self, name):
        proj_dir = os.path.join(os.getcwd(), "projects/{}".format(name))
        os.makedirs(proj_dir, exist_ok=True)
        
        if os.path.exists(os.path.join(proj_dir, "cases.json")):
            if not self.args.addition:
                self.logger.error("Project {} already existed.".format(name))
                return None
        return proj_dir
    
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
    
    def print_args_info(self):
        self.logger.info("[*] proj: {}".format(self.args.proj))
        self.logger.info("[*] hash: {}".format(self.args.get))
        self.logger.info("[*] url: {}".format(self.args.url))
        self.logger.info("[*] key: {}".format(self.args.key))
        self.logger.info("[*] max_retrieval: {}".format(self.args.max_retrieval))
        self.logger.info("[*] filter_by_reported: {}".format(self.args.filter_by_reported))
        self.logger.info("[*] filter_by_closed: {}".format(self.args.filter_by_closed))
        self.logger.info("[*] filter_by_kernel: {}".format(self.args.filter_by_kernel))
        self.logger.info("[*] filter_by_c_prog: {}".format(self.args.filter_by_c_prog))
        self.logger.info("[*] filter_by_fixes_tag: {}".format(self.args.filter_by_fixes_tag))

    def save_cases(self, cases, name):
        cases_json_path = os.path.join(self.proj_dir, "cases.json")
        with open(cases_json_path, 'w') as f:
            json.dump(cases, f)
            f.close()
        self.logger.info("Created a new project {}".format(name))