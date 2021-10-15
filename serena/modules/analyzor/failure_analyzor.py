import os

from serena.infra.tool_box import extrace_call_trace, extract_debug_info, regx_get
from serena.infra.strings import source_file_regx
from serena.modules.analyzor import AnalysisModule
from .error import CannotFindConfigForObject

class FailureAnalysis(AnalysisModule):
    def __init__(self, logger, vendor, report=None, upstream_src=None, vendor_src=None) -> None:
        super().__init__()
        self.logger = logger
        self.vendor = vendor
        self.report = report
        self.upstream_src = upstream_src
        self.vendor_src = vendor_src
        self.config_cache = {}

        self.calltrace = None
        self.vul_module = None
        self.config_cache['vendor_config_path'] = ''

    def run(self):
        self.calltrace = extrace_call_trace(self.report)
        for each_line in self.calltrace:
            dbg_info = extract_debug_info(each_line)
            if dbg_info == None:
                continue
            src_file = regx_get(source_file_regx, dbg_info, 0)
            if src_file == None:
                continue

            if not self._module_check(src_file):
                self.logger.info("Vendor {0} does not have {1} module enabled".format(self.vendor, self.vul_module))
    
    def _module_check(self, upstream_src_file):
        """
        Check config for amd64 only
        """
        basename = os.path.basename(upstream_src_file)
        dirname = os.path.dirname(upstream_src_file)
        full_dirname = os.path.join(self.upstream_src, dirname)
        makefile = os.path.join(full_dirname, "Makefile")

        if basename.endswith(".h"):
            return True
        
        vul_obj = basename[:-2] + '.o'
        config = None
        with open(makefile, "r") as f:
            texts = f.readlines()
            obj2config = self._parse_makefile(texts)
            if vul_obj not in obj2config:
                raise CannotFindConfigForObject(vul_obj)
            config = obj2config[vul_obj]
            self.logger.debug("Matching config {}".format(config))

        vendor_config_path = os.path.join(self.vendor_src, "debian.master/config/amd64/config.common.amd64")
        if self.config_cache['vendor_config_path'] != vendor_config_path:
            self.config_cache = {}
            self.config_cache['vendor_config_path'] = vendor_config_path
            with open(vendor_config_path, "r") as f:
                texts = f.readlines()
                for line in texts:
                    if line[0] == "#":
                        continue
                    i = line.index('=')
                    self.config_cache[line[:i]] = line[i+1:]

        if config not in self.config_cache \
                or (self.config_cache[config] == 'n'):
            return False
        else:
            return True
