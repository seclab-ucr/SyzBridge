from logging import NOTSET
import shutil

from os import path
from subprocess import Popen, call, PIPE, STDOUT
from infra.tool_box import *
from .error import *
from modules.reproducer import *

reserve_port = 7
class Case(Reproducer):
    def __init__(self, index, owner, case_hash, case):
        self.cfg = owner.cfg
        self.args = owner.args
        self.index = index
        self.debug = self.args.debug
        self.case_hash = case_hash[:7]
        self.path_serena = os.getcwd()
        self.path_project = owner.proj_dir
        self.path_package = os.path.join(self.path_serena, "serena")
        self.path_case = self._get_case_path()
        self.case = case
        self.has_c_repro = True
        if self.args.ssh_key != None:
            self.cfg.ssh_key = self.args.ssh_key[0]
        if self.args.ssh_port != None:
            self.cfg.ssh_port = self.args.ssh_port + index * reserve_port
        else:
            self.cfg.ssh_port += index * reserve_port
        if self.args.image != None:
            self.cfg.image_path = self.args.image[0]
        if self.args.vmlinux != None:
            self.cfg.vmlinux_path = self.args.vmlinux[0]
        self._init_case()
        Reproducer.__init__(self, self.path_case, self.cfg.ssh_port, self.case_logger, self.debug, 3)
    
    def create_finish_repro(self):
        self._create_stamp("FINISH_REPRO")
    
    def check_finish_repro(self):
        return self._check_stamp("FINISH_REPRO")
    
    def save_to_others(self):
        dirname = os.path.dirname(self.path_case)
        folder = os.path.basename(dirname)
        self._save_to(folder)
        return folder
    
    def save_to_completed(self):
        self._save_to("completed")
    
    def save_to_succeed(self):
        self._save_to("succeed")
    
    def save_to_error(self):
        self._save_to("error")
    
    def _init_case(self):
        dst = "{}/incomplete/{}".format(self.path_project, self.case_hash)
        if os.path.exists(self.path_case):
            if not os.path.exists(dst):
                shutil.move(self.path_case, dst)
                self.path_case = dst
        else:
            os.makedirs(self.path_case, exist_ok=True)
        
        self.case_logger = init_logger(self.path_case+"/log", 
            cus_format='%(asctime)s %(message)s',
            debug=self.debug, propagate=self.debug)
        
        c_prog = self.case["c_repro"]
        if c_prog == None:
            c_prog == ""
            self.has_c_repro = False
            return
        
        script = os.path.join(self.path_package, "scripts/init-case.sh")
        chmodX(script)
        self.case_logger.info("run: scripts/init-case.sh")
        p = Popen([script, self.path_case, self.cfg.vendor_image, str(self.cfg.vmlinux), self.cfg.ssh_key, c_prog],
                stdout=PIPE,
                stderr=STDOUT)
        with p.stdout:
            log_anything(p.stdout, self.case_logger, self.debug)
        exitcode = p.wait()
        self.case_logger.info("scripts/init-case.sh was done with exitcode {}".format(exitcode))
    
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
    
    def _create_stamp(self, stamp):
        dst = "{}/.stamp/{}".format(self.case_path, stamp)
        call(['touch',dst])
    
    def _check_stamp(self, stamp):
        dst = "{}/.stamp/{}".format(self.case_path, stamp)
        return os.path.exists(dst)