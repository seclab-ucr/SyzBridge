import logging
import os, shutil
import json

from subprocess import call
from infra.config.config import Config
from infra.console.message import ConsoleMessage
from deployer.case import Case
from .error import *

logger = logging.getLogger(__name__)

class AnalysisModule:
    NAME = "MainAnalysisModule"
    ERROR = 0
    INFO = 1
    DEBUG = 2

    def __init__(self):
        self.logger = logger
        self.finish = False
        self.results = {}
        self.report = []
        self.path_case_plugin = ''
        self._prepared = False
        self._move_to_success = False
        self._move_to_success = False
        self._analyzor = None
    
    def init(self, manager: Case):
        if not isinstance(manager, Case):
            raise AnalysisModuleError("setup() requires class Case")

        self.manager = manager
        self.case = manager.case
        self.args = manager.args
        self.case_hash = manager.case_hash
        self.case_logger = manager.case_logger
        self.main_logger = manager.logger
        self.cfg: Config = manager.cfg
        self.path_case = manager.path_case
        self.path_project = manager.path_project
        self.path_package = manager.path_package
        self.lts = manager.lts
        self.index = manager.index
        self.debug = manager.debug
        self.console_mode = manager.console_mode
        self.console_msg: ConsoleMessage = manager.console_msg

    def setup(self):
        if self.NAME == AnalysisModule.NAME:
            return
        self.path_case_plugin = os.path.join(self.path_case, self.NAME)
        self._build_plugin_folder()
        self.logger = self._get_child_logger(self.case_logger)

    def install_analyzor(self, analyzor):
        if not isinstance(analyzor, AnalysisModule):
            raise AnalysisModuleError("install_analyzor() requires class AnalysisModule")
        self.analyzor = analyzor
        self._get_analyzor_results_offline()
    
    @property
    def name(self):
        if self.analyzor == None:
            return "NULL"
        return self.analyzor.NAME
    
    @property
    def analyzor(self):
        return self._analyzor
    
    @analyzor.setter
    def analyzor(self, value):
        self._analyzor = value
    
    def check(func):
        def inner(self):
            if self.analyzor == None:
                raise AnalysisModuleError("Can not run analyzor when it is still NULL")
            try:
                ret = func(self)
            except Exception as e:
                self.case_logger.exception("[{}] Exception happens: {}".format(self.analyzor.NAME, e))
                self.main_logger.exception("Case {} caught exception in plugin {}: {}".format(self.case_hash, self.analyzor.NAME, e))
                return False
            return ret
        return inner
    
    @check
    def run(self):
        self.main_logger.info("Running {}".format(self.analyzor.NAME))
        self.update_console_routine(self.analyzor.NAME)
        ret = self.analyzor.run()
        self.analyzor.dump_results()
        self._set_plugin_status(ret)
        self.analyzor.cleanup()
        return ret
    
    @check
    def prepare(self, **kwargs):
        self.main_logger.debug("Preparing {}".format(self.analyzor.NAME))
        if not self._check_dependencies_finished():
            return False
        return self.analyzor.prepare(**kwargs)

    @check
    def generate_report(self):
        self.main_logger.debug("Generating report from {}".format(self.analyzor.NAME))
        return self.analyzor.generate_report()
    
    @check
    def success(self):
        return self.analyzor.success()
    
    @check
    def check_stamp(self):
        """
        Bool: True if stamp found, otherwise return False
        """
        stamp = "FINISH_" + self.analyzor.NAME.upper()
        ret = self._check_stamp(stamp)
        if ret:
            self.main_logger.info("{} has finished".format(self.analyzor.NAME))
            self.analyzor.set_history_status()
        return ret
    
    @check
    def create_stamp(self):
        stamp = "FINISH_" + self.analyzor.NAME.upper()
        self.main_logger.info("Finish {}".format(self.analyzor.NAME))
        return self._create_stamp(stamp)
    
    def null_results(self):
        plugin = self.cfg.get_plugin(self.analyzor.NAME)
        if plugin == None:
            return False
        plugin.instance.results = None
        plugin.instance.finish = False
    
    def plugin_finished(self, plugin_name):
        plugin = self.cfg.get_plugin(plugin_name)
        if plugin == None:
            return False
        return plugin.instance.finish

    def cleanup(self):
        pass

    def dump_results(self):
        json.dump(self.results, open(os.path.join(self.path_case_plugin, "results.json"), 'w'))
    
    def set_history_status(self):
        self.console_msg.module[self.NAME] = [ConsoleMessage.INFO, "", ""]
        self.manager.send_to_console()

    def update_console_routine(self, module_name):
        if not self.console_mode:
            return
        self.console_msg.message = module_name
        self.console_msg.type = ConsoleMessage.INFO
        self.console_msg.module[module_name] = [ConsoleMessage.INFO, "Preparing {}".format(module_name), ""]
        self.manager.send_to_console()

    def set_stage_text(self, text):
        self.console_msg.type = ConsoleMessage.INFO
        self.console_msg.module[self.NAME] = [ConsoleMessage.INFO, text, ""]
        self.manager.send_to_console()
    
    def set_stage_status(self, status):
        self.console_msg.module[self.NAME][2] = status
        self.manager.send_to_console()
    
    def err_msg(self, msg):
        if self.console_mode:
            self.console_msg.module[self.NAME] = [ConsoleMessage.ERROR, msg, ""]
            self.console_msg.type = ConsoleMessage.INFO
        self.logger.error(msg)
    
    def info_msg(self, msg):
        self.logger.info(msg)
    
    def debug_msg(self, msg):
        self.logger.debug(msg)

    def _get_analyzor_results_offline(self):
        plugin = self.cfg.get_plugin(self.analyzor.NAME)
        res = self._read_analyzor_results()
        if res == None:
            plugin.instance.finish = False
        else:
            plugin.instance.finish = True
            plugin.instance.results = res
        return
    
    def _set_plugin_status(self, ret):
        plugin = self.cfg.get_plugin(self.analyzor.NAME)
        plugin.instance.finish = ret
    
    def _read_analyzor_results(self):
        plugin_path = os.path.join(self.path_case, self.analyzor.NAME)
        results_path = os.path.join(plugin_path, "results.json")
        if not os.path.exists(results_path):
            return None
        try:
            res = json.load(open(results_path, 'r'))
        except:
            return None
        return res

    def _check_dependencies_finished(self):
        plugin = self.cfg.get_plugin(self.analyzor.NAME)
        if plugin != None:
            if plugin.dependency == "weak":
                return True
        dependencies = self.analyzor.DEPENDENCY_PLUGINS
        for plugin in dependencies:
            if not self._check_stamp("FINISH_" + plugin.upper()):
                self.analyzor.logger.error("{} is not finished before {}, terminate {}".format(plugin, self.analyzor.NAME, self.analyzor.NAME))
                return False
        return True
    
    def _build_plugin_folder(self):
        if os.path.exists(self.path_case_plugin):
            for i in range(1, 100):
                if not os.path.exists( self.path_case_plugin+"-{}".format(i)):
                    shutil.move(self.path_case_plugin, self.path_case_plugin+"-{}".format(i))
                    break
                if i == 99:
                    raise PluginFolderReachMaximumNumber
        os.makedirs(self.path_case_plugin, exist_ok=True)
    
    def _log_subprocess_output(self, pipe):
        for line in iter(pipe.readline, b''):
            self.logger.info(line)
    
    def _create_stamp(self, stamp):
        dst = "{}/.stamp/{}".format(self.path_case, stamp)
        call(['touch',dst])
    
    def _check_stamp(self, stamp):
        dst = "{}/.stamp/{}".format(self.path_case, stamp)
        return os.path.exists(dst)

    def _remove_stamp(self, stamp):
        dst = "{}/.stamp/{}".format(self.path_case, stamp)
        if os.path.exists(dst):
            os.remove(dst)
    
    def _init_module(self, module):
        if not isinstance(module, AnalysisModule):
            raise AnalysisModuleError("_init_module() requires class AnalysisModule")
        module.init(self.manager)
        module.setup()
        return module
    
    def _write_to(self, content, file):
        with open("{}".format(file), "w") as f:
            f.write(content)
            f.truncate()

    def _get_child_logger(self, logger):
        child_logger = logger.getChild(self.NAME)
        child_logger.propagate = self.debug
        child_logger.setLevel(logger.level)

        handler = logging.FileHandler("{}/log".format(self.path_case_plugin))
        format = logging.Formatter('[{}] %(asctime)s %(message)s'.format(self.NAME))
        handler.setFormatter(format)
        child_logger.addHandler(handler)
        return child_logger