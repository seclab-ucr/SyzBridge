import os, logging

from infra.tool_box import init_logger
from plugins import AnalysisModule

class Template(AnalysisModule):
    NAME = "Template"
    REPORT_START = "======================Template Report======================"
    REPORT_END =   "==================================================================="
    REPORT_NAME = "Report_Template"
    DEPENDENCY_PLUGINS = []

    def __init__(self):
        super().__init__()
        
    def prepare(self):
        plugin = self.cfg.get_plugin(self.NAME)
        if plugin == None:
            self.err_msg("No such plugin {}".format(self.NAME))
        try:
            self.greeting = int(plugin.greeting)
        except AttributeError:
            self.err_msg("Failed to get greeting")
            return False
        return self.prepare_on_demand()
    
    def prepare_on_demand(self):
        self._prepared = True
        return True
    
    def success(self):
        return self._move_to_success

    def run(self):
        """
        do something
        True: plugin runs smoothly
        False: something failed, stamp will not be created
        """
        self.logger.info("Hello you, {}".format(self.greeting))
        return True
    
    def generate_report(self):
        final_report = "\n".join(self.report)
        self.info_msg(final_report)
        self._write_to(final_report, self.REPORT_NAME)
    
    def _write_to(self, content, name):
        file_path = "{}/{}".format(self.path_case_plugin, name)
        super()._write_to(content, file_path)

    def cleanup(self):
        super().cleanup()
