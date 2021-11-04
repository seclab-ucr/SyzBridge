import os

from . import AnalysisModule
from syzmorph.modules.vm import VMInstance
from subprocess import Popen, PIPE, STDOUT
from infra.tool_box import chmodX, log_anything, regx_match

class TraceAnalysis(AnalysisModule):
    NAME = "TraceAnalysis"
    REPORT_START = "======================TraceAnalysis Report======================"
    REPORT_END =   "==================================================================="
    REPORT_NAME = "Report_TraceAnalysis"

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
        trace_vendor = self.get_vendor_trace()
        trace_upstream = self.get_upstream_trace()
        ret = self.analyze_trace(trace_vendor, trace_upstream)
        return ret
    
    def get_vendor_trace(self):
        pass

    def _launch_vendor_kernel(self):
        vmtype = getattr(VMInstance, self.cfg.vendor_name.upper())
        self.repro.setup(vmtype)
        qemu = self.repro.launch_qemu(self.case_hash, log_name="qemu-{}".format(TraceAnalysis.REPORT_NAME))
    
    def generate_report(self):
        final_report = "\n".join(self.report)
        self.logger.info(final_report)
        self._write_to(final_report, TraceAnalysis.REPORT_NAME)

