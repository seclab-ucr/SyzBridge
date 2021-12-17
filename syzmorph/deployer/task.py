import os

from toposort import toposort, toposort_flatten, CircularDependencyError
from plugins import AnalysisModule, AnalysisModuleError

class Task:
    def __init__(self, args):
        self.args = args
        self.task_value = ()
        self._build_tasks()
        self.task = self._get_tasks()
        self.task_class = {}
        self.task_topological_order = []
        self.ts = {}

    def build_task_class(self, task, A):
        if not isinstance(A, AnalysisModule):
            raise AnalysisModuleError("build_task_class need a AnalysisModule class")
        self.task_class[task] = A
    
    def get_task_module(self, task: int):
        if task not in self.task_class:
            return None
        return self.task_class[task]
    
    def iterate_all_tasks(self):
        return self.task_value
    
    def iterate_enabled_tasks(self):
        return self.task_topological_order
    
    def build_plugins_order(self):
        try:
            self.task_topological_order = list(toposort_flatten(self.ts))
        except CircularDependencyError as e:
            message = "Loop dependency found among "
            l = []
            for plugin in e.data:
                l.append(plugin)
            message += " and ".join(l)
            raise Exception(message)
        for each in self.task_topological_order:
            self.enable_tasks(each)
        return True
    
    def enable_tasks(self, cap):
        self.task |= cap

    def _build_tasks(self):
        proj_dir = os.path.join(os.getcwd(), "syzmorph")
        modules_dir = os.path.join(proj_dir, "plugins")
        module_folder = [ cmd for cmd in os.listdir(modules_dir)
                    if not cmd.endswith('.py') and not cmd == "__pycache__" ]
        index = 1
        setattr(Task, "TASK_ALL", 0)
        for each in module_folder:
            cap_text = "TASK_" + each.upper()
            setattr(Task, cap_text, 1 << index)
            self.task_value += (1 << index,)
            index += 1
    
    def _get_tasks(self):
        task = Task.TASK_ALL
        if self.args.bug_reproduce:
            task |= Task.TASK_BUG_REPRODUCE
        if self.args.modules_analysis:
            task |= Task.TASK_MODULES_ANALYSIS
        if self.args.lts_analysis:
            task |= Task.TASK_LTS_ANALYSIS
        if self.args.trace_analysis:
            task |= Task.TASK_TRACE_ANALYSIS
        if self.args.capability_check:
            task |= Task.TASK_CAPABILITY_CHECK
        return task
    
    def _capable(self, cap):
        return self.task & cap or self.task == Task.TASK_ALL