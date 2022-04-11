import logging
import os, shutil

from subprocess import call
from deployer.case import Case
from .error import *

logger = logging.getLogger(__name__)

class AnalysisModule:
    NAME = "MainAnalysisModule"

    def __init__(self):
        self.logger = logger
        self._move_to_success = False
        self._analyzor = None

    def setup(self, manager):
        if not isinstance(manager, Case):
            raise AnalysisModuleError("setup() requires class Case")

        self.manager = manager
        self.case = manager.case
        self.args = manager.args
        self.case_hash = manager.case_hash
        self.case_logger = manager.case_logger
        self.main_logger = manager.logger
        self.cfg = manager.cfg
        self.path_case = manager.path_case
        self.path_project = manager.path_project
        self.path_package = manager.path_package
        self.lts = manager.lts
        self.index = manager.index
        self.debug = manager.debug
        if self.NAME == AnalysisModule.NAME:
            return
        self.path_case_plugin = os.path.join(self.path_case, self.NAME)
        self._build_plugin_folder()
        self.logger = self._get_child_logger(self.case_logger)

    def install_analyzor(self, analyzor):
        if not isinstance(analyzor, AnalysisModule):
            raise AnalysisModuleError("install_analyzor() requires class AnalysisModule")
        self.analyzor = analyzor
    
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
                return AnalysisModuleError("Can not run analyzor when it is still NULL")
            try:
                ret = func(self)
            except Exception as e:
                logging.exception("Case {} caught exception in plugin {}".format(self.case_hash, self.NAME))
                self.case_logger.error("[{}] Exception happens: {}".format(self.analyzor.NAME, e))
                self.main_logger.error("[{}] Exception happens: {}".format(self.analyzor.NAME, e))
                return None
            return ret
        return inner
    
    @check
    def run(self):
        self.main_logger.info("Running {}".format(self.analyzor.NAME))
        ret = self.analyzor.run()
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
        return ret
    
    @check
    def create_stamp(self):
        stamp = "FINISH_" + self.analyzor.NAME.upper()
        self.main_logger.info("Finish {}".format(self.analyzor.NAME))
        return self._create_stamp(stamp)
    
    def cleanup(self):
        pass
    
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
        module.setup(self.manager)
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