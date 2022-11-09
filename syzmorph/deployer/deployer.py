import os

from psutil import Popen

from infra.tool_box import STREAM_HANDLER, FILE_HANDLER, init_logger, convert_folder_name_to_plugin_name
from infra.strings import *
from plugins import AnalysisModule, AnalysisModuleError
from plugins.modules_analysis import ModulesAnalysis
from infra.console.message import ConsoleMessage
from .case import Case
from .error import *
from .task import Task
from modules.vm import VMInstance
from subprocess import Popen, PIPE, STDOUT

class Deployer(Case, Task):

    def __init__(self, index, owner, case_hash, case):
        Case.__init__(self, index, owner, case_hash, case)
        kernel = case["kernel"]
        try:
            if case["kernel"].startswith("https"):
                kernel = case["kernel"].split('/')[-1].split('.')[0]
        except:
            pass
        if owner.args.console:
            self.console_queue = owner.console_queue
        else:
            self.console_queue = None
        self.console_msg = ConsoleMessage(self.case_hash, index)
        handler_type = STREAM_HANDLER
        if self.console_mode:
            handler_type = FILE_HANDLER
        self.logger = init_logger(__name__+str(self.index), 
            cus_format='%(asctime)s Thread {}: {}[{}] %(message)s'.format(self.index, self.case_hash, kernel).format(self.index),
            debug=self.debug, propagate=self.debug, handler_type=handler_type)
        self.case_logger.info("Initializing deployer")
        Task.__init__(self, self.args)
        self.analysis = AnalysisModule()
        self.analysis.init(self)
        self.analysis.setup()
        self._build_analyzor_modules()
        self._build_plugins_order()
        if self.console_mode:
            self._send_plugins_order_to_console()
    
    # Install a analysis module(plugin) for next use. 
    # This function must be called ahead of using that module(plugin). 
    # It returns the same module object as the argument.
    def use_module(self, module):
        if not isinstance(module, AnalysisModule):
            raise AnalysisModuleError
        
        self.analysis.install_analyzor(module)
        module.init(self)
        return module
    
    # Let deployer run a specific analysis task. Each task represents a specific plugin. 
    # This function takes care of installing module, prepare analysis, running analysis, generating report and creating stamp.
    def do_task(self, task):
        analyzor_module = self.get_task_module(task)
        self.case_logger.info("Start task {}".format(analyzor_module.NAME))
        self.use_module(analyzor_module)
        if not self.analysis.check_stamp():
            analyzor_module.setup()
            if not self.analysis.prepare():
                self.logger.error("Fail to prepare {}".format(self.analysis.name))
                return 1
            try:
                if self.analysis.run():
                    self.analysis.generate_report()
                    self.analysis.create_stamp()
                else:
                    self.analysis.null_results()
            except PluginRuntimeError:
                return 1
            self.case_logger.info("task {} has finished".format(analyzor_module.NAME))
            if not self._success:
                self._success = self.analysis.success()
        return 0
    
    # deploy is the main entrance of Deploy object. 
    # This function iterates all enabled tasks, runs corresponding analysis and save bugs to their folders.
    def deploy(self):
        error = False
        for task in self.iterate_enabled_tasks():
            if self.capable(task) and not self.is_service(task):
                if self.do_task(task) == 1:
                    error = True

        self.case_logger.info("Case finished")
        if self._success:
            self.save_to_succeed()
            self.logger.info("Copy to succeed")
            return True
        else:
            folder = self.save_to_others(error)
            self.logger.info("Copy to {}".format(folder))
            return False
    
    # This function provides a interface that you can run another SyzMorph instance
    # It returns the stnadar output of this instance
    def call_syzmorph(self, cmd, args):
        out = []
        run_cmd = ['python3', 'syzmorph', cmd]
        run_cmd.extend(args)
        p = Popen(run_cmd, stdout=PIPE, stderr=STDOUT, shell=False, cwd=self.path_syzmorph, env=os.environ.copy())
        with p.stdout:
            try:
                for line in iter(p.stdout.readline, b''):
                    try:
                        line = line.decode("utf-8").strip('\n').strip('\r')
                    except:
                        continue
                    out.append(line)
            except ValueError:
                if p.stdout.close:
                    return out
        return out
    
    def _build_analyzor_modules(self):
        res = []
        proj_dir = os.path.join(os.getcwd(), "syzmorph")
        modules_dir = os.path.join(proj_dir, "plugins")
        module_folder = [ cmd for cmd in os.listdir(modules_dir)
                    if not cmd.endswith('.py') and not cmd == "__pycache__" ]
        for each in module_folder:
            if not self.cfg.is_plugin_enabled(convert_folder_name_to_plugin_name(each)):
                continue
            cap_text = "TASK_" + each.upper()
            task_id = getattr(Task, cap_text)
            if self.capable(task_id):
                A = self._get_plugin_instance_by_name(convert_folder_name_to_plugin_name(each))
                self._build_dependency_module(task_id, A)
                self.build_task_class(task_id, A)
    
    def _send_plugins_order_to_console(self):
        res = []
        order = self.iterate_enabled_tasks()
        for task in order:
            if self.capable(task) and not self.is_service(task):
                module = self.get_task_module(task)
                res.append(module.NAME)
        self.console_msg.type = ConsoleMessage.PLUGINS_ORDER
        self.console_msg.message = res
        self.send_to_console()

    def send_to_console(self):
        if self.console_queue != None:
            self.console_queue.put(self.console_msg.__dict__, block=True)
    
    def _build_dependency_module(self, task_id, module: AnalysisModule):
        dst_node = set()
        if task_id not in self.ts:
            self.ts[task_id] = set()
        else:
            return
        for dependency in module.DEPENDENCY_PLUGINS:
            if self.cfg.get_plugin(module.NAME).dependency == "strong" or \
                    (self.cfg.get_plugin(module.NAME).dependency == "weak" and self.module_capable(dependency)):
                depend_cap_text = self.module_name_to_task(dependency)
                try:
                    A = self._get_plugin_instance_by_name(dependency)
                except AttributeError as e:
                    self.logger.error("Fail to plugin {} that is dependent to {}".format(dependency, module.NAME))
                    raise e
                dst_node.add(getattr(Task, depend_cap_text))
                self._build_dependency_module(getattr(Task, depend_cap_text), A)
                self.build_task_class(getattr(Task, depend_cap_text), A)
        self.ts[task_id] = dst_node

    def _get_plugin_instance_by_name(self, name):
        plugin = self.cfg.get_plugin(name)
        return plugin.instance
    
    def _write_to(self, hash_val, name):
        with open("{}/{}".format(self.path_project, name), "a+") as f:
            f.write(hash_val[:7]+"\n")
    