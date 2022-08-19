import os, logging

from infra.tool_box import init_logger
from plugins import AnalysisModule

class TraceValidation(AnalysisModule):
    NAME = "TraceValidation"
    REPORT_START = "======================TraceValidation Report======================"
    REPORT_END =   "==================================================================="
    REPORT_NAME = "Report_TraceValidation"
    DEPENDENCY_PLUGINS = []

    def __init__(self):
        super().__init__()
        
    def prepare(self, trace_map: dict):
        return self.prepare_on_demand(trace_map)
    
    def prepare_on_demand(self, trace_map: dict):
        self.trace_map = trace_map
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
        return True
    
    def generate_report(self):
        self._cleanup()
        final_report = "\n".join(self.report)
        self.info_msg(final_report)
        self._write_to(final_report, self.REPORT_NAME)
    
    def _write_to(self, content, name):
        file_path = "{}/{}".format(self.path_case_plugin, name)
        super()._write_to(content, file_path)

    def _cleanup(self):
        pass
