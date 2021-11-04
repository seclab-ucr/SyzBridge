from . import AnalysisModule

class Template(AnalysisModule):
    NAME = "Template"
    REPORT_START = "======================Template Report======================"
    REPORT_END =   "==================================================================="
    REPORT_NAME = "Report_Template"

    def __init__(self):
        super().__init__()
        self.report = ''
        
    def prepare(self):
        return self.prepare_on_demand()
    
    def prepare_on_demand(self):
        self._prepared = True
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
        self._write_to(final_report, Template.REPORT_NAME)

