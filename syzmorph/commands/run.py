import multiprocessing, threading
import os, stat, sys
import json, gc, logging

from commands import Command
from infra.error import *
from deployer.deployer import Deployer

sys.path.append(os.getcwd())
from queue import Empty
from subprocess import call

logger = logging.getLogger(__name__)
class RunCommand(Command):
    def __init__(self):
        super().__init__()
        self.lock = threading.Lock()
        self.manager = multiprocessing.Manager()
        self.queue = self.manager.Queue()
        self.rest = 0
        self.total = 0
        self.cases = None
        self.proj_dir = None
        self.cfg = None
        
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
        parser.add_argument('--failure-analysis', action='store_true',
                            help='Run failure analysis on target project')
        parser.add_argument('--lts-analysis', action='store_true',
                            help='Run LTS analysis on target project')
        parser.add_argument('--bug-reproduce', action='store_true',
                            help='Run bug reproduce on target project')
        parser.add_argument('--trace-analysis', action='store_true',
                            help='Run trace analysis on target project')

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
        return cases

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

    def parse_config(self, config):
        from syzmorph.infra.config import Config
        
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
        print("[*] proj: {}".format(self.args.proj))
        task = "[*] task: "
        if self.args.failure_analysis:
            task += "failure_analysis "
        print(task)
        if self.cfg != None:
            print("[*] vendor image: {}".format(self.cfg.vendor_image))
            print("[*] vmlinux: {}".format(self.cfg.vmlinux))
            print("[*] ssh_port: {}".format(self.cfg.ssh_port))
            print("[*] ssh_key: {}".format(self.cfg.ssh_key))
            print("[*] vendor_src: {}".format(self.cfg.vendor_src))
            print("[*] vendor_name: {}".format(self.cfg.vendor_name))
    
    def build_work_dir(self):
        os.makedirs(os.path.join(self.proj_dir, "incomplete"), exist_ok=True)
        os.makedirs(os.path.join(self.proj_dir, "completed"), exist_ok=True)
        os.makedirs(os.path.join(self.proj_dir, "succeed"), exist_ok=True)
        os.makedirs(os.path.join(self.proj_dir, "error"), exist_ok=True)
    
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
        
        self.print_args_info()
        
        self.queue = self.manager.Queue()
        self.proj_dir = os.path.join(os.getcwd(), "projects/{}".format(args.proj))

        self.cases = self.read_cases(args.proj)
        if args.case != None:
            self.cases = {args.case: self.cases[args.case]}
        self.build_work_dir()

        for key in self.cases:
            self.queue.put(key)
        
        parallel_max = int(self.args.parallel_max)
        l = list(self.cases.keys())
        self.total = len(l)
        self.rest = self.manager.Value('i', self.total)
        for i in range(0,min(parallel_max,self.total)):
            x = threading.Thread(target=self.prepare_cases, args=(i,), name="lord-{}".format(i))
            x.start()