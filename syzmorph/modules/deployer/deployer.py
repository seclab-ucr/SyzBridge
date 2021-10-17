import os
import re

from infra.tool_box import STREAM_HANDLER, init_logger, regx_match, request_get
from infra.strings import *
from modules.reproducer import Reproducer
from modules.analyzor import AnalysisModule, AnalysisModuleError
from modules.analyzor.failure_analyzor import FailureAnalysis
from .case import Case
from .error import *

class Deployer(Case):
    TASK_ALL = 1 << 0
    TASK_REPRODUCE = 1 << 1
    TASK_FAILURE_ANALYSIS = 1 << 2

    def __init__(self, index, owner, case_hash, case):
        Case.__init__(self, index, owner, case_hash, case)
        self.logger = init_logger(__name__+str(self.index), 
            cus_format='%(asctime)s Thread {}: %(message)s'.format(self.index),
            debug=self.debug, propagate=self.debug, handler_type=STREAM_HANDLER)
        self.case_logger.info("https://syzkaller.appspot.com/bug?id={}".format(case_hash))
        self.analysis = AnalysisModule()
        self.task = self._get_tasks()
        self._reproduce_success = False
    
    def use_module(self, module):
        if not isinstance(module, AnalysisModule):
            raise AnalysisModuleError
        
        module.setup(self)
        self.analysis.install_analyzor(module)
        return module
    
    def deploy(self):
        if self._capable(Deployer.TASK_REPRODUCE):
            if not self.has_c_repro:
                self.logger.error("{} does not have a valid C reproducer".format(self.case_hash))
                return
            #try:
            ret = self.deploy_reproducer()
            if ret != None:
                self.logger.info("Trigger a Kasan bug: {}".format(ret))
                self._reproduce_success = True
        
        if self._capable(Deployer.TASK_FAILURE_ANALYSIS):
            if not self._reproduce_success:
                self.logger.info("{} is ready for failure analysis".format(self.case_hash))
                self.failure_analysis()
            else:
                self.logger.info("{} has succeed in bug reproducing, no need for failure analysis.".format(self.case_hash))
        
        if self._reproduce_success:
            self.save_to_succeed()
            self.logger.info("Copy to succeed")
        else:
            folder = self.save_to_others()
            self.logger.info("Copy to {}".format(folder))
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
        rep = request_get(self.case['report'])
        self.use_module(FailureAnalysis(rep.text))
        self.analysis.run()
        self.analysis.generate_report()
    
    def _get_tasks(self):
        task = Deployer.TASK_ALL
        if self.args.failure_analysis:
            task |= Deployer.TASK_FAILURE_ANALYSIS
        
        return task
    
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
                            self._write_to(self.case_hash, "DoubleFree")
                            flag_double_free = True
                            break
                    if regx_match(kasan_write_addr_regx, line) and not flag_kasan_write:
                            ret = True
                            self.logger.info("KASAN MemWrite")
                            self._write_to(self.case_hash, "MemWrite")
                            flag_kasan_write = True
                            break
                    if regx_match(kasan_read_addr_regx, line) and not flag_kasan_read:
                            ret = True
                            self.logger.info("KASAN MemRead")
                            self._write_to(self.case_hash, "MemRead")
                            flag_kasan_read = True
                            break
        return ret, title
    
    def _write_to(self, hash_val, name):
        with open("{}/{}".format(self.path_project, name), "a+") as f:
            f.write(hash_val[:7]+"\n")
    
    def _capable(self, cap):
        return self.task & cap or self.task == Deployer.TASK_ALL
    