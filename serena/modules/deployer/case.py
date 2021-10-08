from logging import NOTSET
import shutil

from os import path
from subprocess import Popen, call, PIPE, STDOUT
from serena.infra.tool_box import *
from .error import *
from serena.modules.reproducer import *

base_ssh_port = 36777
reserve_port = 7

class Case(Reproducer):
    def __init__(self, index, case_hash, args, case, debug=False):
        self.index = index
        self.debug = debug
        self.case_hash = case_hash[:7]
        self.path_project = os.getcwd()
        self.path_package = os.path.join(self.path_project, "serena")
        self.path_case = self._get_case_path()
        self.case = case
        self.ssh_port = base_ssh_port + index * reserve_port
        self.ssh_key = args.ssh_key[0]
        self.args = args
        self.has_c_repro = True
        self.image_path = ""
        self.vmlinux_path = ""
        self.logger = init_logger(__name__+str(self.index), 
            cus_format='%(asctime)s Thread {}: %(message)s'.format(self.index),
            debug=self.debug, propagate=self.debug, handler_type=STREAM_HANDLER)
        if args.ssh != None:
            self.ssh_port = args.ssh + index * reserve_port
        self._init_case()
        Reproducer.__init__(self, self.path_case, self.ssh_port, self.case_logger, self.debug, 3)
    
    def create_finish_repro(self):
        self._create_stamp("FINISH_REPRO")
    
    def check_finish_repro(self):
        return self._check_stamp("FINISH_REPRO")
    
    def save_to_completed(self):
        self._save_to("completed")
    
    def save_to_succeed(self):
        self._save_to("succeed")
    
    def save_to_error(self):
        self._save_to("error")
    
    def _init_case(self):
        dst = "{}/work/incomplete/{}".format(self.path_project, self.case_hash)
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
        
        if self.args.image != None:
            self.image_path = self.args.image[0]
        if self.args.vmlinux != None:
            self.vmlinux_path = self.args.vmlinux[0]
        
        script = os.path.join(self.path_package, "scripts/init-case.sh")
        chmodX(script)
        self.logger.info("run: scripts/init-case.sh")
        p = Popen([script, self.path_case, self.image_path, self.vmlinux_path, self.ssh_key, c_prog],
                stdout=PIPE,
                stderr=STDOUT)
        with p.stdout:
            log_anything(p.stdout, self.case_logger, self.debug)
        exitcode = p.wait()
        self.logger.info("scripts/init-case.sh was done with exitcode {}".format(exitcode))
    
    def _get_case_path(self):
        path_case = None
        path_work = os.path.join(self.path_project, "work")
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
            path_case = "{}/work/incomplete/{}".format(self.path_project, self.case_hash)
        return path_case
    
    def _save_to(self, folder):
        self.case_logger.info("Copy to {}".format(folder))
        src = self.path_case
        base = os.path.basename(src)
        dst = "{}/work/{}/{}".format(self.path_project, folder, base)
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