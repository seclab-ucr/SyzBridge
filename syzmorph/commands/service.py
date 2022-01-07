import os
import logging
import threading
import json
import multiprocessing
import gc
import importlib

from datetime import datetime, timedelta
from time import sleep
from pytz import timezone, utc
from syzmorph.commands import Command
from deployer.deployer import Deployer
from syzmorph.modules.syzbot import Crawler
from infra.error import *

from queue import Empty

logger = logging.getLogger(__name__)

class ServiceCommand(Command):
    def __init__(self):
        super().__init__()
        self.lock = threading.Lock()
        self.manager = multiprocessing.Manager()
        self.queue = self.manager.Queue()
        self.skiped = False

    def add_arguments(self, parser):
        super().add_arguments(parser)
        # Mandatory
        parser.add_argument('--proj', nargs='?', action='store',
                            help='project name')
        parser.add_argument('--config', nargs='?', action='store',
                            help='config file. Will be overwritten by arguments if conflict.')
        parser.add_argument('--url', nargs='?', action='store',
                            default="https://syzkaller.appspot.com/upstream",
                            help='Indicate an URL for automatically crawling and running.\n'
                                '(default value is \'https://syzkaller.appspot.com/upstream\')')
        parser.add_argument('--key', action='append', default=[],
                            help='The keywords for detecting cases.\n'
                                '(By default, it retrieve all cases)\n'
                                'This argument could be multiple values')
                                
        # Task          
        self.add_arguments_for_plugins(parser)          

        # Regular arguments
        parser.add_argument('--image', nargs=1, action='store',
                            help='Linux image for bug reproducing')
        parser.add_argument('--vmlinux', nargs='?', action='store',
                            help='vmlinux for debugging')
        parser.add_argument('-pm', '--parallel-max', nargs='?', action='store',
                            default='1', help='The maximum of parallel processes\n'
                                            '(default valus is 1)')
        parser.add_argument('--ssh-port', nargs='?', action='store',
                            help='The default port of ssh using by QEMU\n'
                            '(default port is 36777)')
        parser.add_argument('--ssh-key', nargs=1, action='store',
                            help='The private key for ssh connection')
        parser.add_argument('--filter-by-c-prog', action='store_true',
                            help='filter bugs do not have a c reproducer\n')
        parser.add_argument('--skip-today', action='store_true',
                            help='Skip crawling cases today\n')
    
    def add_arguments_for_plugins(self, parser):
        proj_dir = os.path.join(os.getcwd(), "syzmorph")
        modules_dir = os.path.join(proj_dir, "plugins")
        module_folder = [ cmd for cmd in os.listdir(modules_dir)
                    if not cmd.endswith('.py') and not cmd == "__pycache__" ]
        for module_name in module_folder:
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
        return parser.add_parser(cmd, help='Run syzmorph as system service.')

    def parse_config(self, config):
        from syzmorph.infra.config.config import Config
        
        cfg = Config()
        cfg.load_from_file(config)

        return cfg

    def check_essential_args(self):
        if self.args.proj == None:
            logger.error("--proj must be specified.")
            return True
        if self.args.config == None and \
                (self.args.image == None or self.args.ssh_key == None):
            logger.error("--image or --ssh-key must be specified or pass --config to import them from a config file.")
            return True
        return False

    def print_args_info(self):
        print("[*] proj: {}".format(self.proj_dir))
        if self.cfg != None:
            for vendor in self.cfg.kernel.__dict__:
                t = getattr(self.cfg.kernel, vendor)
                print("=========={}==========".format(t.distro_name))
                print("[*] vendor image: {}".format(t.distro_image))
                print("[*] vmlinux: {}".format(t.vmlinux))
                print("[*] ssh_port: {}".format(t.ssh_port))
                print("[*] ssh_key: {}".format(t.ssh_key))
                print("[*] distro_src: {}".format(t.distro_src))
                print("[*] distro_name: {}".format(t.distro_name))
    
    def build_work_dir(self):
        os.makedirs(os.path.join(self.proj_dir, "incomplete"), exist_ok=True)
        os.makedirs(os.path.join(self.proj_dir, "completed"), exist_ok=True)
        os.makedirs(os.path.join(self.proj_dir, "succeed"), exist_ok=True)
        os.makedirs(os.path.join(self.proj_dir, "error"), exist_ok=True)
    
    def read_cases(self, name):
        cases = {}
        work_path = os.getcwd()
        cases_json_path = os.path.join(work_path, "projects/{}/cases.json".format(name))
        if os.path.exists(cases_json_path):
            with open(cases_json_path, 'r') as f:
                cases = json.load(f)
                f.close()
        return cases

    def save_cases(self, cases, name):
        cases_json_path = os.path.join(self.proj_dir, "cases.json")
        with open(cases_json_path, 'w') as f:
            json.dump(cases, f)
            f.close()
        print("Created a new project {}".format(name))
    
    def get_daily_cases(self):
        self.cases = self.read_cases(self.args.proj)
        bk_cases = self.cases.copy()
        if not self.args.skip_today or self.skiped:
            crawler = Crawler(url=self.args.url, keyword=self.args.key,  
                filter_by_c_prog=int(self.args.filter_by_c_prog), debug=self.args.debug, log_path = self.proj_dir)

            crawler.run()
            for hash_val in crawler.cases:
                if hash_val in self.cases and self.finished_case(hash_val):
                    del crawler.cases[hash_val]
            self.cases = crawler.cases
        if self.args.skip_today:
            self.skiped = True
        print("[+] {} new cases in syzbot today.".format(len(self.cases)))
        bk_cases.update(self.cases)
        self.save_cases(bk_cases, self.proj_dir)
        return self.cases
    
    def finished_case(self, hash_val):
        hash_val = hash_val[:7]
        return os.path.exists(os.path.join(self.proj_dir, "completed", hash_val)) or \
            os.path.exists(os.path.join(self.proj_dir, "succeed", hash_val)) or \
            os.path.exists(os.path.join(self.proj_dir, "error", hash_val))
    
    def deploy_one_case(self, index, hash_val):
        case = self.cases[hash_val]
        dp = Deployer(owner=self, index=index, case_hash=hash_val, case=case)
        dp.deploy()
        del dp

    def prepare_cases(self, index,):
        while(1):
            self.lock.acquire(blocking=True)
            try:
                hash_val = self.queue.get(block=True, timeout=3)
                print("Thread {}: run case {} [{}/{}] left".format(index, hash_val, self.rest.value-1, self.total))
                self.rest.value -= 1
                self.lock.release()
                x = multiprocessing.Process(target=self.deploy_one_case, args=(index, hash_val,), name="lord-{}".format(index))
                x.start()
                x.join()
                gc.collect()
            except Empty:
                self.lock.release()
                break
        print("Thread {} exit->".format(index))
    
    def get_cur_time(self):
        la = timezone('America/Los_Angeles')
        now = datetime.now().astimezone(la)
        return now
    
    def run(self, args):
        self.args = args
        if self.check_essential_args():
            return

        try:
            if self.args.config != None:
                self.cfg = self.parse_config(self.args.config)
        except TargetFileNotExist as e:
            logger.error(e)
            return
        except ParseConfigError as e:
            logger.error(e)
            return
        except TargetFormatNotMatch as e:
            logger.error(e)
            return
        
        self.proj_dir = os.path.join(os.getcwd(), "projects/{}".format(args.proj))
        self.print_args_info()
        self.build_work_dir()
        
        self.queue = self.manager.Queue()
        
        while True:
            cases = self.get_daily_cases()
            start_time = self.get_cur_time()
            for key in cases:
                self.queue.put(key)
            
            parallel_max = int(self.args.parallel_max)
            l = list(cases.keys())
            self.total = len(l)
            self.rest = self.manager.Value('i', self.total)
            for i in range(0,min(parallel_max,self.total)):
                x = threading.Thread(target=self.prepare_cases, args=(i,), name="lord-{}".format(i))
                x.start()
            print("[+] Finished today's cases, put into sleep")
            next_start_time = start_time + timedelta(days=1)
            end_time = self.get_cur_time()
            while end_time.date() < next_start_time.date():
                sleep(60*60)
                end_time = self.get_cur_time()
            print("[+] Welcome to a new day")