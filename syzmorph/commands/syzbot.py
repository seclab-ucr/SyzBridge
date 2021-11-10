import os, json

from commands import Command
from infra.tool_box import STREAM_HANDLER, init_logger

class SyzbotCommand(Command):
    def __init__(self):
        super().__init__()
        self.proj_dir = None
        self.logger = init_logger(__name__, handler_type=STREAM_HANDLER)

    def add_arguments(self, parser):
        super().add_arguments(parser)
        parser.add_argument('--get',  nargs='?', action='store',
                            help='To get a case by hash or a file contains multiple hashs.')
        parser.add_argument('--proj',  nargs='?', action='store',
                            help='To save the cases into a project')
        parser.add_argument('--url', nargs='?', action='store',
                            default="https://syzkaller.appspot.com/upstream",
                            help='Indicate an URL for automatically crawling and running.\n'
                                '(default value is \'https://syzkaller.appspot.com/upstream\')')
        parser.add_argument('--key', action='append',
                            help='The keywords for detecting cases.\n'
                                '(By default, it retrieve all cases)\n'
                                'This argument could be multiple values')
        parser.add_argument('--max-retrieval', nargs='?', action='store',
                            default='9999',
                            help='The maximum of cases for retrieval\n'
                                '(By default all the cases will be retrieved)')
        parser.add_argument('--filter-by-reported', nargs='?',
                            default='-1',
                            help='filter bugs by the days they were reported\n')
        parser.add_argument('--filter-by-closed', nargs='?',
                            default='-1',
                            help='filter bugs by the days they were closed\n')
    
    def custom_subparser(self, parser, cmd):
        return parser.add_parser(cmd, help='Get a case by hash or a file contains multiple hashs.')

    def run(self, args):
        self.args = args
        if self.check_essential_args():
            return
        
        self.print_args_info()

        if self.args.key == None:
            self.args.key = ['']
        
        self.proj_dir = self.build_proj_dir(args.proj)
        if self.proj_dir == None:
            return

        from syzmorph.modules.syzbot import Crawler

        crawler = Crawler(url=self.args.url, keyword=self.args.key, max_retrieve=int(self.args.max_retrieval), 
            filter_by_reported=int(self.args.filter_by_reported), filter_by_closed=int(self.args.filter_by_closed), 
            debug=self.args.debug, log_path = self.proj_dir)
        
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
            self.logger.error("Project {} already existed.".format(name))
            return None
        return proj_dir
    
    def print_args_info(self):
        self.logger.info("[*] proj: {}".format(self.args.proj))
        self.logger.info("[*] hash: {}".format(self.args.get))
        self.logger.info("[*] url: {}".format(self.args.url))
        self.logger.info("[*] url: {}".format(self.args.key))
        self.logger.info("[*] max_retrieval: {}".format(self.args.max_retrieval))

    def save_cases(self, cases, name):
        cases_json_path = os.path.join(self.proj_dir, "cases.json")
        with open(cases_json_path, 'w') as f:
            json.dump(cases, f)
            f.close()
        self.logger.info("Created a new project {}".format(name))