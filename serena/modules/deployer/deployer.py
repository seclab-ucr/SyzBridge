import os
import re

from serena.infra.tool_box import STREAM_HANDLER, init_logger, regx_match
from serena.infra.strings import *
from serena.modules.reproducer import Reproducer
from serena.modules.analyzor import AnalysisModule, AnalysisModuleError
from .case import Case
from .error import *

class Deployer(Case):
    ACTION_BUG_REPRODUCE = 0
    def __init__(self, index, args, cfg, action, case_hash, case):
        Case.__init__(self, index, case_hash, args, cfg, case, args.debug)
        self.case_logger.info("https://syzkaller.appspot.com/bug?id={}".format(case_hash))
        self.action = action
    
    def use_module(self, module):
        if not isinstance(module, AnalysisModule):
            raise AnalysisModuleError
        
        module.cfg = self._cfg
        module.setup(self)
        return module
    
    def deploy(self):
        if self.action == Deployer.ACTION_BUG_REPRODUCE:
            if not self.has_c_repro:
                self.logger.error("{} does not have a valid C reproducer".format(self.case_hash))
                return
            #try:
            ret = self.deploy_reproducer()
            if ret != None:
                self.logger.info("Trigger a Kasan bug: {}".format(ret))
                self.logger.info("Copy to succeed")
                self.save_to_succeed()
            else:
                self.failure_analysis()
                self.logger.info("Copy to completed")
                self.save_to_completed()
            #except Exception as e:
            #    self.logger.error(e)
            #    self.logger.info("Copy to error")
            #    self.save_to_error()

    
    def deploy_reproducer(self):
        if self.check_finish_repro():
            self.logger.info("{} already finished reproducing".format(self.case_hash))
            return None
        self.logger.info("start reproducing bugs")
        report, triggered = self.prepare(self.case_hash)
        self.create_finish_repro()
        if triggered:
            is_kasan_bug, title = self._KasanChecker(report)
            if is_kasan_bug:
                return title
        return None
    
    def failure_analysis(self):
        self.analysis.failure_analysis()
    
    def _KasanChecker(self, report):
        title = None
        ret = False
        flag_double_free = False
        flag_kasan_write = False
        flag_kasan_read = False
        if report != []:
            for each in report:
                for line in each:
                    if regx_match(r'BUG: (KASAN: [a-z\\-]+ in [a-zA-Z0-9_]+)', line) or \
                        regx_match(r'BUG: (KASAN: double-free or invalid-free in [a-zA-Z0-9_]+)', line):
                        m = re.search(r'BUG: (KASAN: [a-z\\-]+ in [a-zA-Z0-9_]+)', line)
                        if m != None and len(m.groups()) > 0:
                            title = m.groups()[0]
                        m = re.search(r'BUG: (KASAN: double-free or invalid-free in [a-zA-Z0-9_]+)', line)
                        if m != None and len(m.groups()) > 0:
                            title = m.groups()[0]
                    if regx_match(double_free_regx, line) and not flag_double_free:
                            ret = True
                            self.logger.info("Double free")
                            self.__write_to(self.case_hash, "DoubleFree")
                            flag_double_free = True
                            break
                    if regx_match(kasan_write_addr_regx, line) and not flag_kasan_write:
                            ret = True
                            self.logger.info("KASAN MemWrite")
                            self.__write_to(self.case_hash, "MemWrite")
                            flag_kasan_write = True
                            break
                    if regx_match(kasan_read_addr_regx, line) and not flag_kasan_read:
                            ret = True
                            self.logger.info("KASAN MemRead")
                            self.__write_to(self.case_hash, "MemRead")
                            flag_kasan_read = True
                            break
        return ret, title
    
    def __write_to(self, hash_val, name):
        with open("{}/work/{}".format(self.path_project, name), "a+") as f:
            f.write(hash_val[:7]+"\n")