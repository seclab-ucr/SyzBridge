import multiprocessing, threading
import os, stat, sys
import json, gc

from commands import Command

sys.path.append(os.getcwd())
from queue import Empty
from subprocess import call

class RunCommand(Command):
    def __init__(self, parser):
        super().__init__()
        self.add_arguments(parser)
        self.lock = threading.Lock()
        self.manager = multiprocessing.Manager()
        self.queue = self.manager.Queue()
        self.rest = 0
        self.total = 0
        self.crawler = None
        
    def add_arguments(self, parser):
        parser.add_argument('-i', '--input', nargs='?', action='store',
                            help='The input should be a valid hash or a file contains multiple hashs. -u, -m ,and -k will be ignored if -i is enabled.')
        parser.add_argument('-u', '--url', nargs='?', action='store',
                            default="https://syzkaller.appspot.com/upstream",
                            help='Indicate an URL for automatically crawling and running.\n'
                                '(default value is \'https://syzkaller.appspot.com/upstream\')')
        parser.add_argument('-I', '--image', nargs=1, action='store',
                            help='Linux image for bug reproducing')
        parser.add_argument('-v', '--vmlinux', nargs='?', action='store',
                            help='vmlinux for debugging')
        parser.add_argument('-k', '--key', action='append',
                            help='The keywords for detecting cases.\n'
                                '(By default, it retrieve all cases)\n'
                                'This argument could be multiple values')
        parser.add_argument('-m', '--max', nargs='?', action='store',
                            default='9999',
                            help='The maximum of cases for retrieval\n'
                                '(By default all the cases will be retrieved)')
        parser.add_argument('--filter-by-reported', nargs='?',
                            default='-1',
                            help='filter bugs by the days they were reported\n')
        parser.add_argument('--filter-by-closed', nargs='?',
                            default='-1',
                            help='filter bugs by the days they were closed\n')
        parser.add_argument('--include-high-risk', action='store_true',
                            help='Include high risk bugs for analysis')
        parser.add_argument('--use-cache',
                            action='store_true',
                            help='Read cases from cache, this will overwrite the --input feild')
        parser.add_argument('-pm', '--parallel-max', nargs='?', action='store',
                            default='1', help='The maximum of parallel processes\n'
                                            '(default valus is 1)')
        parser.add_argument('--ssh', nargs='?', action='store',
                            help='The default port of ssh using by QEMU\n'
                            '(default port is 36777)')
        parser.add_argument('--ssh-key', nargs=1, action='store',
                            help='The private key for ssh connection')
        parser.add_argument('--config', nargs=1, action='store',
                            help='config file. Will be overwritten by arguments if conflict.')
        parser.add_argument('--debug', action='store_true',
                            help='Enable debug mode')

    def check_kvm(self):
        proj_path = os.path.join(os.getcwd(), "serena")
        check_kvm_path = os.path.join(proj_path, "scripts/check-kvm.sh")
        st = os.stat(check_kvm_path)
        os.chmod(check_kvm_path, st.st_mode | stat.S_IEXEC)
        r = call([check_kvm_path], shell=False)
        if r == 1:
            exit(0)

    def install_requirments(self):
        proj_path = os.path.join(os.getcwd(), "serena")
        requirements_path = os.path.join(proj_path, "scripts/install-requirements.sh")
        st = os.stat(requirements_path)
        os.chmod(requirements_path, st.st_mode | stat.S_IEXEC)
        call([requirements_path], shell=False)

    def cache_cases(self, cases):
        work_path = os.getcwd()
        cases_json_path = os.path.join(work_path, "work/cases.json")
        with open(cases_json_path, 'w') as f:
            json.dump(cases, f)
            f.close()

    def read_cases_from_cache(self):
        cases = {}
        work_path = os.getcwd()
        cases_json_path = os.path.join(work_path, "work/cases.json")
        if os.path.exists(cases_json_path):
            with open(cases_json_path, 'r') as f:
                cases = json.load(f)
                f.close()
        return cases

    def deploy_one_case(self, index, cfg, hash_val):
        from serena.modules.deployer.deployer import Deployer
        
        case = self.crawler.cases[hash_val]
        dp = Deployer(index=index, args=self.args, cfg=cfg, action=Deployer.ACTION_BUG_REPRODUCE, case_hash=hash_val, case=case)
        dp.deploy()
        del dp

    def prepare_cases(self, index, cfg):
        while(1):
            self.lock.acquire(blocking=True)
            try:
                hash_val = self.queue.get(block=True, timeout=3)
                print("Thread {}: run case {} [{}/{}] left".format(index, hash_val, self.rest.value-1, self.total))
                self.rest.value -= 1
                self.lock.release()
                x = multiprocessing.Process(target=self.deploy_one_case, args=(index, cfg, hash_val,), name="lord-{}".format(index))
                x.start()
                x.join()
                gc.collect()
            except Empty:
                self.lock.release()
                break
        print("Thread {} exit->".format(index))

    def parse_config(self, config):
        from serena.infra.config import Config
        
        cfg = Config()
        cfg.load(config)

        return cfg

    def run(self, args):
        self.args = args
        if self.args.key == None:
            self.args.key = ['']
        self.check_kvm()
        self.install_requirments()

        cfg = None
        if self.args.config != None:
            cfg = self.parse_config(self.args.config)

        from serena.modules.syzbot import Crawler

        crawler = Crawler(url=self.args.url, keyword=self.args.key, max_retrieve=int(self.args.max), 
            filter_by_reported=int(self.args.filter_by_reported), filter_by_closed=int(self.args.filter_by_closed), 
            include_high_risk=self.args.include_high_risk, debug=self.args.debug)
        
        if self.args.input != None:
            if len(self.args.input) == 40:
                crawler.run_one_case(self.args.input)
            else:
                with open(self.args.input, 'r') as f:
                    text = f.readlines()
                    for line in text:
                        line = line.strip('\n')
                        crawler.run_one_case(line)
        else:
            if self.args.use_cache:
                crawler.cases = self.read_cases_from_cache()
            else:
                crawler.run()
        
        if not self.args.use_cache:
            self.cache_cases(crawler.cases) 
        
        self.queue = self.manager.Queue()
        for key in crawler.cases:
            self.queue.put(key)
        
        parallel_max = int(self.args.parallel_max)
        l = list(crawler.cases.keys())
        self.total = len(l)
        self.rest = self.manager.Value('i', self.total)
        for i in range(0,min(parallel_max,self.total)):
            x = threading.Thread(target=self.prepare_cases, args=(i, cfg), name="lord-{}".format(i))
            x.start()