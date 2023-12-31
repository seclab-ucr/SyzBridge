import os
import importlib

from toposort import toposort, toposort_flatten, CircularDependencyError
from plugins import AnalysisModule, AnalysisModuleError
from infra.tool_box import convert_folder_name_to_plugin_name

class Task:
    def __init__(self, args):
        self.args = args
        self._task_value = ()
        self.task = self._build_tasks()
        self._task_class = {}
        self._task_topological_order = []
        self.ts = {}

    def build_task_class(self, task, A):
        if not isinstance(A, AnalysisModule):
            raise AnalysisModuleError("build_task_class need a AnalysisModule class")
        self._task_class[task] = A
    
    def get_task_module(self, task: int):
        if task not in self._task_class:
            return None
        return self._task_class[task]
    
    def get_task_module_by_name(self, name):
        task = Task.TASK_ALL
        try:
            task |= getattr(Task, name.upper())
        except:
            return None
        if task not in self._task_class:
            return None
        return self._task_class[task]
    
    def iterate_all_tasks(self):
        return self._task_value
    
    def iterate_enabled_tasks(self):
        return self._task_topological_order
    
    def _build_plugins_order(self):
        try:
            self._task_topological_order = list(toposort_flatten(self.ts))
        except CircularDependencyError as e:
            message = "Loop dependency found among "
            l = []
            for plugin in e.data:
                l.append(plugin)
            message += " and ".join(l)
            raise Exception(message)
        for each in self._task_topological_order:
            self.enable_tasks(each)
        return True
    
    def enable_tasks(self, cap):
        self.task |= cap

    def _build_tasks(self):
        proj_dir = os.path.join(os.getcwd(), "syzbridge")
        modules_dir = os.path.join(proj_dir, "plugins")
        module_folder = [ cmd for cmd in os.listdir(modules_dir)
                    if not cmd.endswith('.py') and not cmd == "__pycache__" ]
        index = 1
        setattr(Task, "TASK_ALL", 0)
        task = Task.TASK_ALL
        for each in module_folder:
            try:
                if not self.cfg.is_plugin_enabled(convert_folder_name_to_plugin_name(each)):
                    continue
                cap_text = "TASK_" + each.upper()
                setattr(Task, cap_text, 1 << index)
                self._task_value += (1 << index,)
                self.logger.debug("Task: {} {}".format(cap_text, self._task_value))
                index += 1
                if getattr(self.args, each):
                    task |= getattr(Task, cap_text)
            except Exception as e:
                print("Fail to load plugin {}: {}".format(each, e))
                continue
        return task
    
    def module_name_to_task(self, module_name):
        cap_text = "TASK"
        start = 0
        for i in range(len(module_name)):
            c = module_name[i]
            if c.isupper():
                cap_text += module_name[start:i].upper() + "_"
                start = i
        cap_text += module_name[start:].upper()
        return cap_text
    
    def task_to_module_name(self, task):
        if task.find("_") == -1:
            return ""
        return convert_folder_name_to_plugin_name(task[task.find("_")+1:].lower())
    
    def module_capable(self, module_name):
        task = self.module_name_to_task(module_name)
        cap = getattr(Task, task)
        return self.capable(cap)
    
    def capable(self, cap):
        return self.task & cap or self.task == Task.TASK_ALL
    
    def is_service(self, cap):
        module_name = self._task_class[cap].NAME
        return self.cfg.is_plugin_service(module_name)