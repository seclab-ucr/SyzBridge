import os, logging

from syzmorph.infra.tool_box import init_logger
from . import AnalysisModule

class Template(AnalysisModule):
    NAME = "Template"
    REPORT_START = "======================Template Report======================"
    REPORT_END =   "==================================================================="
    REPORT_NAME = "Report_Template"

    def __init__(self):
        super().__init__()
        self.report = ''
        self._prepared = False
        self.path_plugin = ''
        self._move_to_success = False
        self.logger = None
        
    def prepare(self):
        return self.prepare_on_demand()
    
    def prepare_on_demand(self):
        self._prepared = True
        self.logger = self._get_child_logger(self.case_logger)
        return True
    
    def success(self):
        return self._move_to_success

    def run(self):
        """
        do something
        """
        return None
    
    def generate_report(self):
        final_report = "\n".join(self.report)
        self.logger.info(final_report)
        self._write_to(final_report, self.REPORT_NAME)
    
    def _get_child_logger(self, logger):
        child_logger = logger.getChild(self.NAME)
        child_logger.propagate = True
        child_logger.setLevel(logger.level)

        handler = logging.FileHandler("{}/log".format(self.path_plugin))
        format = logging.Formatter('%(message)s')
        handler.setFormatter(format)
        child_logger.addHandler(handler)
        return child_logger

