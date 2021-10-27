import re
import datetime

from infra.tool_box import regx_match, chmodX, set_compiler_version
from . import AnalysisModule
from .error import *
from subprocess import Popen, STDOUT, PIPE
from dateutil import parser as time_parser
from modules.vm import VM
from infra.strings import *

class LtsAnalysis(AnalysisModule):
    NAME = "LtsAnalysis"
    REPORT_START = "======================LTS Analysis Report======================"
    REPORT_END =   "==================================================================="
    REPORT_NAME = "Report_LTSAnalysis"

    def __init__(self):
        super().__init__()
        self.case = None
        self.report = ""
        self._prepared = False
    
    def prepare(self):
        return self.prepare_on_demand()
    
    def prepare_on_demand(self):
        self._prepared = True
        if self.lts == None:
            return False
        return True

    def run(self):
        if not self._prepared:
            self.logger.error("Module {} is not prepared".format(LtsAnalysis.NAME))
            return None
        self.logger.info("Start reproducing bugs on upstream LTS")
        self.build_env_LTS()
        self.repro.setup(VM.LTS)
        self.report, triggered = self.repro.prepare(self.case_hash)
        if triggered:
            is_kasan_bug, title = self._KasanChecker(self.report)
            if is_kasan_bug:
                return title
        return None
    
    def build_env_LTS(self):
        image_switching_date = datetime.datetime(2020, 3, 15)
        time = self.case["time"]
        case_time = time_parser.parse(time)
        if image_switching_date <= case_time:
            image = "stretch"
        else:
            image = "wheezy"
        
        gcc_version = set_compiler_version(time_parser.parse(self.case["time"]), self.case["config"])
        script = "syzmorph/scripts/deploy-linux.sh"
        chmodX(script)
        p = Popen([script, gcc_version, self.path_case, str(self.args.parallel_max), 
                self.case["commit"], self.case["config"], image, self.lts['snapshot'], self.lts["version"], str(self.index)],
            stderr=STDOUT,
            stdout=PIPE)
        with p.stdout:
            self._log_subprocess_output(p.stdout)
        exitcode = p.wait()
        self.logger.info("script/deploy.sh is done with exitcode {}".format(exitcode))
        return exitcode
    
    def generate_report(self):
        final_report = "\n".join(self.report)
        self.logger.info(final_report)
        self._write_to(final_report, LtsAnalysis.REPORT_NAME)
    
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
    
    def _write_to(self, content, name):
        with open("{}/{}".format(self.path_case, name), "w") as f:
            f.write(content)
            f.truncate()
