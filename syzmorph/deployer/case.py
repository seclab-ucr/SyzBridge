import json
import shutil

from os import path
from subprocess import Popen, call, PIPE, STDOUT
from infra.tool_box import *
from .error import *
from modules.reproducer import *

reserve_port = 7
class Case:
    def __init__(self, index, owner, case_hash, case):
        self.cfg = owner.cfg
        self.args = owner.args
        self.index = index
        self.debug = self.args.debug
        self.case_hash = case_hash[:7]
        self.path_syzmorph = os.getcwd()
        self.path_project = owner.proj_dir
        self.path_package = os.path.join(self.path_syzmorph, "syzmorph")
        self.path_case = self._get_case_path()
        self.case = case
        self.lts = None
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
        self._init_case(case_hash)
        #if self.lts != None:
        #    self.path_linux = os.path.join(self.path_case, "linux/linux-{}".format(self.lts["version"]))
        self.path_linux = os.path.join(self.path_case, "linux")
        self.repro = Reproducer(path_linux=self.path_linux, path_case=self.path_case, path_syzmorph=self.path_syzmorph, 
            ssh_port=self.cfg.ssh_port, case_logger=self.case_logger, debug= self.debug, qemu_num=3)
    
    def save_to_others(self):
        dirname = os.path.dirname(self.path_case)
        folder = os.path.basename(dirname)
        if folder == 'incomplete':
            folder = 'completed'
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
        
        self.case_logger = init_logger(self.path_case+"/log", 
            cus_format='%(asctime)s %(message)s',
            debug=self.debug, propagate=self.debug)
        
        self.case_logger.info("https://syzkaller.appspot.com/bug?id={}".format(case_hash))
        
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
        self.lts = self._determine_lts()
    
    def _determine_lts(self):
        vendor_name = self.cfg.vendor_name.lower()
        code_name = self.cfg.vendor_code_name.lower()
        codename2LTS_path = os.path.join(self.path_package, "resources/codename2LTS.json")
        data = self._read_json(codename2LTS_path)
        if vendor_name not in data:
            self.case_logger.error("Cannot find vendor {}, try add it manually in resources/codename2LTS.json".format(vendor_name))
            return None
        if code_name not in data[vendor_name]:
            self.case_logger.error("Cannot find code name {}, try add it manually in resources/codename2LTS.json".format(code_name))
            return None

        if self.cfg.vendor_version == None and len(data[vendor_name][code_name]) > 1:
            self.case_logger.error("Multiple vendor version found in resources/codename2LTS.json, specify a version in config using \"vendor_version\"")
            return None

        for each in data[vendor_name][code_name]:
            if self.cfg.vendor_version != None:
                if each['version'] == self.cfg.vendor_version:
                    return each
            else:
                return each

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
    
    def _read_json(self, json_path):
        with open(json_path, 'r') as f:
            d = json.load(f)
            f.close()
            return d
        return None