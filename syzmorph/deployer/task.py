from plugins import AnalysisModule, AnalysisModuleError

class Task:
    TASK_ALL = 0
    TASK_TEMPLATE = 0
    TASK_BUG_REPRODUCE = 1 << 1
    TASK_FAILURE_ANALYSIS = 1 << 2
    TASK_LTS_ANALYSIS = 1 << 3
    TASK_TRACE_ANALYSIS = 1 << 4
    TASK_CAPABILITY_CHECK = 1 << 5

    def __init__(self, args):
        self.args = args
        self.task = self._get_tasks()
        self.task_class = {}

    def build_task_class(self, task, A):
        if not isinstance(A, AnalysisModule):
            raise AnalysisModuleError("build_task_class need a AnalysisModule class")
        self.task_class[task] = A
    
    def get_task_module(self, task):
        if task not in self.task_class:
            return None
        return self.task_class[task]
    
    def iterate_all_tasks(self):
        return (Task.TASK_LTS_ANALYSIS, Task.TASK_BUG_REPRODUCE, Task.TASK_FAILURE_ANALYSIS, Task.TASK_TRACE_ANALYSIS, Task.TASK_CAPABILITY_CHECK)

    def _get_tasks(self):
        task = Task.TASK_ALL
        if self.args.bug_reproduce:
            task |= Task.TASK_BUG_REPRODUCE
        if self.args.failure_analysis:
            task |= Task.TASK_FAILURE_ANALYSIS
        if self.args.lts_analysis:
            task |= Task.TASK_LTS_ANALYSIS
        if self.args.trace_analysis:
            task |= Task.TASK_TRACE_ANALYSIS
        if self.args.capability_check:
            task |= Task.TASK_CAPABILITY_CHECK
        return task
    
    def _capable(self, cap):
        return self.task & cap or self.task == Task.TASK_ALL