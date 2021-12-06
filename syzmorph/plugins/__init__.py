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
        self.repro = manager.repro
        self.case_hash = manager.case_hash
        self.case_logger = manager.case_logger
        self.main_logger = manager.logger
        self.cfg = manager.cfg
        self.path_case = manager.path_case
        self.path_package = manager.path_package
        self.lts = manager.lts
        self.index = manager.index
        self.debug = manager.debug

    def install_analyzor(self, analyzor):
        if not isinstance(analyzor, AnalysisModule):
            raise AnalysisModuleError("install_analyzor() requires class AnalysisModule")
        self.analyzor = analyzor
    
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
            return func(self)
        return inner
    
    @check
    def run(self):
        self.main_logger.info("Running {}".format(self.analyzor.NAME))
        return self.analyzor.run()
    
    @check
    def prepare(self, **kwargs):
        self.main_logger.debug("Preparing {}".format(self.analyzor.NAME))
        self.analyzor.path_case_plugin = os.path.join(self.path_case, self.analyzor.NAME)
        self._build_plugin_folder()
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
    
    def _build_plugin_folder(self):
        if os.path.exists(self.analyzor.path_case_plugin):
            for i in range(1, 100):
                if not os.path.exists( self.analyzor.path_case_plugin+"-{}".format(i)):
                    shutil.move(self.analyzor.path_case_plugin, self.analyzor.path_case_plugin+"-{}".format(i))
                    break
                if i == 99:
                    raise PluginFolderReachMaximumNumber
        os.makedirs(self.analyzor.path_case_plugin, exist_ok=True)
    
    def _log_subprocess_output(self, pipe):
        for line in iter(pipe.readline, b''):
            self.logger.info(line)
    
    def _create_stamp(self, stamp):
        dst = "{}/.stamp/{}".format(self.path_case, stamp)
        call(['touch',dst])
    
    def _check_stamp(self, stamp):
        dst = "{}/.stamp/{}".format(self.path_case, stamp)
        return os.path.exists(dst)
    
    def _write_to(self, content, file):
        with open("{}".format(file), "w") as f:
            f.write(content)
            f.truncate()
