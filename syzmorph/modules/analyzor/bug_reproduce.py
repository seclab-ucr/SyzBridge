import re

from . import AnalysisModule
from syzmorph.modules.vm import VMInstance
from syzmorph.infra.tool_box import regx_match
from syzmorph.infra.strings import *

class BugReproduce(AnalysisModule):
    NAME = "BugReproduce"
    REPORT_START = "======================BugReproduce Report======================"
    REPORT_END =   "==================================================================="
    REPORT_NAME = "Report_BugReproduce"

    def __init__(self):
        super().__init__()
        self.report = ''
        
    def prepare(self):
        return self.prepare_on_demand()
    
    def prepare_on_demand(self):
        self._prepared = True
        return True
    
    def check(func):
        def inner(self):
            ret = func(self)
            if ret:
                self.main_logger.info("Trigger a Kasan bug: {}".format(ret))
                self._move_to_success = True
            else:
                self.main_logger.info("Fail to trigger the bug")
            return ret
        return inner

    @check
    def run(self):
        self.logger.info("start reproducing bugs on {}".format(self.cfg.vendor_name))
        self.repro.setup(getattr(VMInstance, self.cfg.vendor_name.upper()))
        report, triggered = self.repro.reproduce(self.case_hash)
        if triggered:
            is_kasan_bug, title = self._KasanChecker(report)
            if is_kasan_bug:
                return title
        return None
    
    def success(self):
        return self._move_to_success
    
    def generate_report(self):
        final_report = "\n".join(self.report)
        self.logger.info(final_report)
        self._write_to(final_report, BugReproduce.REPORT_NAME)
    
    def _KasanChecker(self, report):
        title = None
        ret = False
        flag_double_free = False
        flag_kasan_write = False
        flag_kasan_read = False
        if report != []:
            for each in report:
                for line in each:
                    if regx_match(r'BUG: (KASAN: [a-z\\-]+ in [a-zA-Z0-9_]+)', line) or \
                        regx_match(r'BUG: (KASAN: double-free or invalid-free in [a-zA-Z0-9_]+)', line):
                        m = re.search(r'BUG: (KASAN: [a-z\\-]+ in [a-zA-Z0-9_]+)', line)
                        if m != None and len(m.groups()) > 0:
                            title = m.groups()[0]
                        m = re.search(r'BUG: (KASAN: double-free or invalid-free in [a-zA-Z0-9_]+)', line)
                        if m != None and len(m.groups()) > 0:
                            title = m.groups()[0]
                    if regx_match(double_free_regx, line) and not flag_double_free:
                            ret = True
                            self.logger.info("Double free")
                            self._write_to(self.case_hash, "LTSDoubleFree")
                            flag_double_free = True
                            break
                    if regx_match(kasan_write_addr_regx, line) and not flag_kasan_write:
                            ret = True
                            self.logger.info("KASAN MemWrite")
                            self._write_to(self.case_hash, "LTSMemWrite")
                            flag_kasan_write = True
                            break
                    if regx_match(kasan_read_addr_regx, line) and not flag_kasan_read:
                            ret = True
                            self.logger.info("KASAN MemRead")
                            self._write_to(self.case_hash, "LTSMemRead")
                            flag_kasan_read = True
                            break
        return ret, title

