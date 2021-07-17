from logging import NOTSET
import shutil

from os import path
from subprocess import Popen, PIPE, STDOUT
from serena.infra.tool_box import *
from .error import *

base_ssh_port = 36777
reserve_port = 7

class Case:
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
        if args.ssh != None:
            self.ssh_port = args.ssh + index * reserve_port
        self._init_case()
    
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
        self.case_logger.info("run: scripts/init-case.sh")
        p = Popen([script, self.path_case, self.image_path, self.vmlinux_path, self.ssh_key, c_prog],
                stdout=PIPE,
                stderr=STDOUT)
        with p.stdout:
            log_anything(p.stdout, self.case_logger, self.case_logger.level)
        exitcode = p.wait()
        self.case_logger.info("scripts/init-case.sh was done with exitcode {}".format(exitcode))
    
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