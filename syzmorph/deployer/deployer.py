import importlib, os

from infra.tool_box import STREAM_HANDLER, init_logger, request_get
from infra.strings import *
from plugins import AnalysisModule, AnalysisModuleError
from plugins.modules_analysis import ModulesAnalysis
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
        self.build_plugins_order()
        self._success = False
    
    def use_module(self, module):
        if not isinstance(module, AnalysisModule):
            raise AnalysisModuleError
        
        self.analysis.install_analyzor(module)
        return module
    
    def do_task(self, task):
        analyzor_module = self.get_task_module(task)
        self.use_module(analyzor_module)
        if not self.analysis.check_stamp():
            analyzor_module.setup(self)
            if not self.analysis.prepare():
                self.logger.error("Fail to prepare {}".format(self.analysis.name))
                return 1
            self.analysis.run()
            self.analysis.generate_report()
            self.analysis.create_stamp()
            if not self._success:
                self._success = self.analysis.success()
        return 0
    
    def deploy(self):
        error = False
        for task in self.iterate_enabled_tasks():
            if self._capable(task):
                if self.do_task(task) == 1:
                    error = True

        if self._success:
            self.save_to_succeed()
            self.logger.info("Copy to succeed")
        else:
            folder = self.save_to_others(error)
            self.logger.info("Copy to {}".format(folder))
    
    def build_analyzor_modules(self):
        res = []
        proj_dir = os.path.join(os.getcwd(), "syzmorph")
        modules_dir = os.path.join(proj_dir, "plugins")
        module_folder = [ cmd for cmd in os.listdir(modules_dir)
                    if not cmd.endswith('.py') and not cmd == "__pycache__" ]
        for each in module_folder:
            cap_text = "TASK_" + each.upper()
            task_id = getattr(Task, cap_text)
            if self._capable(task_id):
                A = self._get_plugin_by_name(each)
                self._build_dependency_module(task_id, A)
                self.build_task_class(task_id, A)
    
    def _build_dependency_module(self, task_id, module):
        dst_node = set()
        if task_id not in self.ts:
            self.ts[task_id] = set()
        else:
            return
        for dependency in module.DEPENDENCY_PLUGINS:
            depend_cap_text = self._get_dependency_name(dependency)
            plugin_name = depend_cap_text[depend_cap_text.find("_")+1:].lower()
            A = self._get_plugin_by_name(plugin_name)
            dst_node.add(getattr(Task, depend_cap_text))
            self._build_dependency_module(getattr(Task, depend_cap_text), A)
            self.build_task_class(getattr(Task, depend_cap_text), A)
        self.ts[task_id] = dst_node

    def _get_plugin_by_name(self, name):
        module = importlib.import_module("plugins.{}".format(name))
        class_name = self._get_analyzor_class_name(name)
        new_class = getattr(module, class_name)
        A = new_class()
        return A
    
    def _get_dependency_name(self, dependency):
        cap_text = "TASK"
        start = 0
        for i in range(len(dependency)):
            c = dependency[i]
            if c.isupper():
                cap_text += dependency[start:i].upper() + "_"
                start = i
        cap_text += dependency[start:].upper()
        return cap_text
    
    def _get_analyzor_class_name(self, file):
        res = ''
        texts = file.split('_')
        for each in texts:
            res += each[0].upper() + each[1:]
        return res
    
    def _write_to(self, hash_val, name):
        with open("{}/{}".format(self.path_project, name), "a+") as f:
            f.write(hash_val[:7]+"\n")
    