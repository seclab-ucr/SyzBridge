import logging

from subprocess import check_call, run
from modules.deployer.case import Case
from .error import AnalysisModuleError

logger = logging.getLogger(__name__)

class AnalysisModule:
    NAME = "MainAnalysisModule"

    def __init__(self):
        self.logger = logger
        self._analyzor = None

    def setup(self, manager):
        if not isinstance(manager, Case):
            raise AnalysisModuleError("setup() requires class Case")

        self.logger = manager.case_logger
        self.cfg = manager.cfg
        self.path_case = manager.path_case
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
            func(self)
        return inner
    
    @check
    def run(self):
        self.logger.debug("Running {}".format(self.analyzor.NAME))
        return self.analyzor.run()
    
    @check
    def generate_report(self):
        self.logger.debug("Generating report from {}".format(self.analyzor.NAME))
        return self.analyzor.generate_report()
