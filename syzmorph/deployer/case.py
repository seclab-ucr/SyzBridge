import json
import shutil

from os import path
from subprocess import Popen, call, PIPE, STDOUT
from infra.tool_box import *
from .error import *
from modules.reproducer import *
from infra.config.config import Config

reserve_port = 7
class Case:
    def __init__(self, index, owner, case_hash, case):
        self.cfg: Config = self.parse_config(owner.args.config)
        self.args = owner.args
        self.index = index
        self.debug = self.args.debug
        self.case_hash = case_hash[:7]
        self._success = False
        self.path_syzmorph = os.getcwd()
        self.path_project = owner.proj_dir
        self.path_package = os.path.join(self.path_syzmorph, "syzmorph")
        self.path_case = self._get_case_path()
        self.path_ori = self.path_case
        self.case = case
        self.lts = None
        self.has_c_repro = True
        self.path_linux = ""
        self.console_mode = self.args.console
        self._init_case(case_hash)
        #if self.lts != None:
        #    self.path_linux = os.path.join(self.path_case, "linux/linux-{}".format(self.lts["version"]))
    
    def parse_config(self, config):
        cfg = Config()
        cfg.load_from_file(config)

        return cfg

    def save_to_others(self, error):
        dirname = os.path.dirname(self.path_ori)
        folder = os.path.basename(dirname)
        if folder == 'incomplete':
            folder = 'completed'
        if folder == 'error':
            folder = 'completed'
        if error:
            folder = 'error'
        self._save_to(folder)
        return folder
    
    def save_to_completed(self):
        self._save_to("completed")
    
    def save_to_succeed(self):
        self._save_to("succeed")
    
    def save_to_error(self):
        self._save_to("error")
    
    def _init_case(self, case_hash):
        dst = "{}/incomplete/{}".format(self.path_project, self.case_hash)
        if os.path.exists(self.path_case):
            if not os.path.exists(dst):
                shutil.move(self.path_case, dst)
                self.path_case = dst
        else:
            os.makedirs(self.path_case, exist_ok=True)
        
        self.path_linux = os.path.join(self.path_case, "linux")
        
        self.case_logger = init_logger(self.path_case+"/log", 
            cus_format='%(asctime)s %(message)s',
            debug=self.debug, propagate=self.debug)
        
        self.case_logger.info("https://syzkaller.appspot.com/bug?id={}".format(case_hash))
        
        c_prog = self.case["c_repro"]
        if c_prog == None:
            c_prog = ""
            self.has_c_repro = False
        
        script = os.path.join(self.path_package, "scripts/init-case.sh")
        chmodX(script)
        self.case_logger.info("run: scripts/init-case.sh")
        p = Popen([script, self.path_case, c_prog],
                stdout=PIPE,
                stderr=STDOUT)
        with p.stdout:
            log_anything(p.stdout, self.case_logger, self.debug)
        exitcode = p.wait()
        self.case_logger.info("scripts/init-case.sh was done with exitcode {}".format(exitcode))

        for kernel in self.cfg.get_all_kernels():
            if self.need_repro(kernel.distro_name) or kernel.type == 1: # If need reproduce or type is upstream kernel
                kernel.repro = Reproducer(cfg=kernel, manager=self)
        #self.lts = self._determine_lts()
    """
    def _determine_lts(self):
        distro_name = self.cfg.distro_name.lower()
        code_name = self.cfg.distro_code_name.lower()
        codename2LTS_path = os.path.join(self.path_package, "resources/codename2LTS.json")
        data = self._read_json(codename2LTS_path)
        if distro_name not in data:
            self.case_logger.error("Cannot find vendor {}, try add it manually in resources/codename2LTS.json".format(distro_name))
            return None
        if code_name not in data[distro_name]:
            self.case_logger.error("Cannot find code name {}, try add it manually in resources/codename2LTS.json".format(code_name))
            return None

        if self.cfg.distro_version == None and len(data[distro_name][code_name]) > 1:
            self.case_logger.error("Multiple vendor version found in resources/codename2LTS.json, specify a version in config using \"distro_version\"")
            return None

        for each in data[distro_name][code_name]:
            if self.cfg.distro_version != None:
                if each['version'] == self.cfg.distro_version:
                    return each
            else:
                return each
    """

    def need_repro(self, distro_name):
        if self.case['affect'] != None:
            if distro_name in self.case['affect']:
                return True 
        else:
            if self.case['patch']['fixes'] == []:
                return True
            for fix in self.case['patch']['fixes']:
                if distro_name in fix['exclude']:
                    return False
            return True

    def _get_case_path(self):
        path_case = None
        path_work = self.path_project
        dirs = os.listdir(path_work)
        for each_dir in dirs:
            if not os.path.isdir("{}/{}".format(path_work, each_dir)):
                continue
            sub_dir = os.path.join(path_work, each_dir)
            cases = os.listdir(sub_dir)
            if self.case_hash in cases:
                path_case = os.path.join(sub_dir, self.case_hash)
                if each_dir == 'succeed':
                    self._success = True
                break
        
        if path_case == None:
            path_case = "{}/incomplete/{}".format(self.path_project, self.case_hash)
        return path_case
    
    def _save_to(self, folder):
        self.case_logger.info("Copy to {}".format(folder))
        src = self.path_case
        base = os.path.basename(src)
        dst = "{}/{}/{}".format(self.path_project, folder, base)
        if os.path.isdir(dst):
            try:
                os.rmdir(dst)
            except:
                self.case_logger.error("Fail to remove directory: {}".format(dst))
        shutil.move(src, dst)
        self.path_case = dst
    
    def _read_json(self, json_path):
        with open(json_path, 'r') as f:
            d = json.load(f)
            f.close()
            return d
        return None