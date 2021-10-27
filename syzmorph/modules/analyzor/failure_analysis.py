import os

from infra.tool_box import extrace_call_trace, extract_debug_info, regx_get, regx_getall, regx_match, request_get
from infra.strings import source_file_regx
from . import AnalysisModule
from .error import *

class FailureAnalysis(AnalysisModule):
    NAME = "FailureAnalysis"
    REPORT_START = "======================Failure Analysis Report======================"
    REPORT_END =   "==================================================================="
    REPORT_NAME = "Report_FailureAnalysis"

    def __init__(self):
        super().__init__()
        self.kasan_report = None
        self.config_cache = {}
        self._prepared = False

        self.calltrace = None
        self.vul_module = None
        self.cfg = None
        self.report = []
        self.config_cache['vendor_config_path'] = ''
    
    def check(func):
        def inner(self):
            ret = func(self)
            if func(self):
                self.main_logger.info("[Failure analysis] All modules passed")
            else:
                self.main_logger.info("[Failure analysis] At least one module failed to find in {}".format(self.cfg.vendor_name))
            return ret
        return inner
    
    def prepare(self):
        report = request_get(self.case['report'])
        return self.prepare_on_demand(report.text)
    
    def prepare_on_demand(self, report):
        self._prepared = True
        self.kasan_report = report.split('\n')
        if self.kasan_report == []:
            return False
        return True

    @check
    def run(self):
        res = True

        if not self._prepared:
            self.logger.error("Module {} is not prepared".format(FailureAnalysis.NAME))
            return False
        self.report.append(FailureAnalysis.REPORT_START)
        self.calltrace = extrace_call_trace(self.kasan_report)
        for each_line in self.calltrace:
            dbg_info = extract_debug_info(each_line)
            if dbg_info == None:
                continue
            vul_src_file = regx_get(source_file_regx, dbg_info, 0)
            if vul_src_file == None:
                raise AnalysisModuleError("Can not extract source file from \"{}\"".format(dbg_info))

            if self.module_check(vul_src_file):
                self.report.append("Check {} ---> Pass".format(vul_src_file))
            else:
                self.logger.info("Vendor {0} does not have {1} module enabled".format(self.cfg.vendor_name, self.vul_module))
                self.report.append("Check {} ---> Fail".format(vul_src_file))
                res = False
        self.report.append(FailureAnalysis.REPORT_END)
        return res
    
    def generate_report(self):
        final_report = "\n".join(self.report)
        self.logger.info(final_report)
        self._write_to(final_report, FailureAnalysis.REPORT_NAME)
    
    def module_check(self, upstream_vul_src_file):
        """
        Check config for amd64 only
        """
        basename = os.path.basename(upstream_vul_src_file)
        dirname = os.path.dirname(upstream_vul_src_file)

        if regx_match(r'arch/x86', dirname):
            return True
        if basename.endswith(".h"):
            return True
        
        vul_obj = basename[:-2]
        self.vul_module = vul_obj
        try:
            config = self._find_config_in_vendor(vul_obj, dirname)
            if config == None:
                # if can not find target Makefile 
                # or can not find target config in Makefile
                # return True
                return True
        except CannotFindConfigForObject:
            return False

        vendor_config_path = os.path.join(self.cfg.vendor_src, "debian/build/build-generic/.config")
        if not os.path.exists(vendor_config_path):
            raise CannotFindKernelConfig
        if self.config_cache['vendor_config_path'] != vendor_config_path:
            self.config_cache = {}
            self.config_cache['vendor_config_path'] = vendor_config_path
            with open(vendor_config_path, "r") as f:
                texts = f.readlines()
                for line in texts:
                    if line[0] == "#":
                        continue
                    try:
                        i = line.index('=')
                        self.config_cache[line[:i]] = line[i+1:].strip()
                    except ValueError:
                        pass

        if config not in self.config_cache \
                or (self.config_cache[config] == 'n'):
            return False
        else:
            return True
    
    def _find_config_in_vendor(self, vul_obj, dirname):
        while dirname != "":
            full_dirname = os.path.join(self.cfg.vendor_src, dirname)
            makefile = os.path.join(full_dirname, "Makefile")

            self.logger.debug("Finding {} at {}".format(vul_obj, makefile))
            config = None
            if not os.path.exists(makefile):
                return None
            with open(makefile, "r") as f:
                texts = f.readlines()
                config = self._find_obj_in_Makefile(vul_obj, texts)
                if config == None:
                    raise CannotFindConfigForObject(vul_obj)
                if config == 'y':
                    # if vulnerable object was enabled by obj-y,
                    # go back to it's parent folder to find config
                    # for this vulnerable folder
                    self.logger.debug("{} was enabled by obj-y. Go to the outer Makefile".format(vul_obj))
                    vul_obj = os.path.basename(dirname)
                    dirname = os.path.dirname(dirname)
                else:
                    self.logger.debug("Matching config {}".format(config))
                    return config
        return None

    def _find_obj_in_Makefile(self, vul_obj, content):
        assignment = r'=|:=|\+='
        obj_config = r'(CONFIG_\w+)'
        obj_o = r'([a-zA-Z0-9_-]+)\.o|([a-zA-Z0-9_-]+)/'

        value = None

        for line in content:
            if line[0] == '#' or line[0] == '\n' or regx_match(r'endif', line):
                value = None
            if regx_match(assignment, line):
                value = 'y'
            v = regx_get(obj_config, line, 0)
            if v != None:
                value = v
            objects = regx_getall(obj_o, line)
            for each_obj in objects:
                if  value == None:
                    break
                for e in each_obj:
                    if e == vul_obj:
                        return value
    
    def _write_to(self, content, name):
        with open("{}/{}".format(self.path_case, name), "w") as f:
            f.write(content)
            f.truncate()

