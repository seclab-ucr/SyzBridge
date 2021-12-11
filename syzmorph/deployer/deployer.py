import importlib, os

from infra.tool_box import STREAM_HANDLER, init_logger, request_get
from infra.strings import *
from plugins import AnalysisModule, AnalysisModuleError
from plugins.failure_analysis import FailureAnalysis
from .case import Case
from .error import *
from .task import Task
from modules.vm import VMInstance

class Deployer(Case, Task):

    def __init__(self, index, owner, case_hash, case):
        Case.__init__(self, index, owner, case_hash, case)
        Task.__init__(self, self.args)
        self.logger = init_logger(__name__+str(self.index), 
            cus_format='%(asctime)s Thread {}: {} %(message)s'.format(self.index, self.case_hash).format(self.index),
            debug=self.debug, propagate=self.debug, handler_type=STREAM_HANDLER)
        self.analysis = AnalysisModule()
        self.analysis.setup(self)
        self.build_analyzor_modules()
        self._success = False
    
    def use_module(self, module):
        if not isinstance(module, AnalysisModule):
            raise AnalysisModuleError
        
        module.setup(self)
        self.analysis.install_analyzor(module)
        return module
    
    def do_task(self, task):
        analyzor_module = self.get_task_module(task)
        self.use_module(analyzor_module)
        if not self.analysis.check_stamp():
            if not self.analysis.prepare():
                self.logger.error("Something wrong when preparing {}".format(self.analysis.NAME))
                return
            self.analysis.run()
            self.analysis.generate_report()
            self.analysis.create_stamp()
            if not self._success:
                self._success = self.analysis.success()
    
    def deploy(self):
        for task in self.iterate_all_tasks():
            if self._capable(task):
                self.do_task(task)

        if self._success:
            self.save_to_succeed()
            self.logger.info("Copy to succeed")
        else:
            folder = self.save_to_others()
            self.logger.info("Copy to {}".format(folder))
    
    def build_analyzor_modules(self):
        res = []
        proj_dir = os.path.join(os.getcwd(), "syzmorph")
        modules_dir = os.path.join(proj_dir, "plugins")
        module_folder = [ cmd for cmd in os.listdir(modules_dir)
                    if not cmd.endswith('.py') and not cmd == "__pycache__" ]
        for each in module_folder:
            cap_text = "TASK_" + each.upper()
            if self._capable(getattr(Task, cap_text)):
                module = importlib.import_module("plugins.{}".format(each))
                class_name = self._get_analyzor_class_name(each)
                new_class = getattr(module, class_name)
                A = new_class()
                self.build_task_class(getattr(Task, cap_text), A)
    
    def _get_analyzor_class_name(self, file):
        res = ''
        texts = file.split('_')
        for each in texts:
            res += each[0].upper() + each[1:]
        return res
    
    def _write_to(self, hash_val, name):
        with open("{}/{}".format(self.path_project, name), "a+") as f:
            f.write(hash_val[:7]+"\n")
    