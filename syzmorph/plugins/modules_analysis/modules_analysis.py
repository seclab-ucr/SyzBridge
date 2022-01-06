import os, random
from posixpath import basename, dirname

from infra.tool_box import *
from infra.strings import source_file_regx
from plugins import AnalysisModule
from plugins.error import *
from plugins.trace_analysis import TraceAnalysis
from infra.ftraceparser.trace import Trace
from modules.vm import VM, VMInstance

class TraceAnalysisError(Exception):
    pass
class ModulesAnalysis(AnalysisModule):
    NAME = "ModulesAnalysis"
    REPORT_START = "======================Modules Analysis Report======================"
    REPORT_END =   "==================================================================="
    REPORT_NAME = "Report_ModulesAnalysis"
    DEPENDENCY_PLUGINS = ["TraceAnalysis"]

    def __init__(self):
        super().__init__()
        self.kasan_report = None
        self.config_cache = {}
        self._prepared = False
        self._move_to_success = False

        self.vul_module = None
        self.cfg = None
        self.path_case_plugin = None
        self.report = []
        self._cur_distro = None
        self.config_cache['vendor_config_path'] = ''
        self._loadable_modules = {}
        self._ftrace_functions = {}
    
    def check(func):
        def inner(self):
            ret = func(self)
            if ret:
                self.main_logger.info("[Modules analysis] All modules passed")
            else:
                self.main_logger.info("[Modules analysis] At least one module failed to find in {}".format(self._cur_distro.distro_name))
            return ret
        return inner
    
    def prepare(self):
        report = request_get(self.case['report'])
        self._build_loadable_modules()
        return self.prepare_on_demand(report.text)
    
    def prepare_on_demand(self, report):
        self._prepared = True
        self.kasan_report = report.split('\n')
        if self.kasan_report == []:
            return False
        return True
    
    def success(self):
        return self._move_to_success

    @check
    def run(self):
        res = True
        if not self._prepared:
            self.logger.error("Module {} is not prepared".format(ModulesAnalysis.NAME))
            return False
        self.report.append(ModulesAnalysis.REPORT_START)

        self.logger.info("[Modules analysis] Checking modules in KASAN report")
        res = self.check_kasan_report()
        self.logger.info("[Modules analysis] Checking modules in ftrace")
        try:
            self.check_ftrace()
        except TraceAnalysisError as e:
            self.logger.error("[Modules analysis] {}".format(e))
                
        self.report.append(ModulesAnalysis.REPORT_END)
        return res
    
    def check_ftrace(self):
        trace = self._open_trace()
        if trace == None:
            raise TraceAnalysisError("Failed to open trace file: file do not exist")
        vm = self._prepare_gdb()
        check_map = {}
        all_distros = self.cfg.get_distros()
        for distro in all_distros:
            distro.build_module_list()
            check_map[distro.distro_name] = {}

        trace.add_filter("task", "==\"poc\"")
        begin_node = trace.find_node(0)
        while begin_node != None:
            if begin_node.parent is None and begin_node.is_function and not trace.is_filtered(begin_node):
                if all_distros == []:
                    return False
                if not self.check_modules_in_trace(begin_node, vm, check_map, all_distros):
                    return False
            begin_node = begin_node.next_node_by_time
        return True
    
    def check_modules_in_trace(self, begin_node, vm, check_map, all_distros):
        end_node = begin_node.scope_end_node
        while begin_node != end_node:
            if begin_node.is_function:
                src_file = self.get_src_file_from_function(begin_node, vm)
                if src_file != None:
                    for distro in all_distros:
                        self._cur_distro = distro
                        if src_file in check_map[distro.distro_name]:
                            continue
                        if dirname(src_file) == "mm":
                            """
                            If moduels are in mm/, we ignore them because different allocators 
                            usually don't make any differences
                            """
                            continue
                        check_map[distro.distro_name][src_file] = True
                        ret = self.module_check(distro, src_file)
                        if ret == 0:
                            self.report.append(begin_node.text)
                            self.logger.info("Vendor {0} does not have {1} module enabled".format(distro.distro_name, self.vul_module))
                            self.report.append("Module {} from {} is not enabled in {}".format(self.vul_module, src_file, distro.distro_name))
                        if ret == 2:
                            self.report.append(begin_node.text)
                            user = 'root'
                            if self.check_module_privilege(self.vul_module):
                                user = 'normal user'
                            self.report.append("[{}] Module {} from {} need to be loaded in {} ".format(user, self.vul_module, src_file, distro.distro_name))
                        if ret == 3:
                            self.report.append(begin_node.text)
                            self.report.append("Module {} from {} need root to be loaded".format(self.vul_module, src_file))
            begin_node = begin_node.next_node
        return True

    def _prepare_gdb(self):
        linux = os.path.join(self.path_case, "linux")
        upstream = self.cfg.get_upstream()
        vmlinux = upstream.repro.vmlinux
        image = upstream.repro.image_path
        key = upstream.repro.ssh_key
        vm = VM(linux=linux, cfg=upstream, vmlinux=vmlinux, key=key, tag='{} upstream'.format(self.case_hash),
            port=random.randint(1024, 65535), image=image, hash_tag=self.case_hash)
        vm.gdb_attach_vmlinux()
        return vm
    
    def get_src_file_from_function(self, begin_node, vm):
        if begin_node.function_name in self._ftrace_functions:
            return None
        self._ftrace_functions[begin_node.function_name] = True
        addr = vm.get_func_addr(begin_node.function_name)
        if addr == 0:
            return None
        file, _ = vm.get_dbg_info(addr)
        return file
        
    def check_kasan_report(self):
        res = {}
        for distro in self.cfg.get_distros():
            res[distro.distro_name] = True
        calltrace = extrace_call_trace(self.kasan_report)
        self.report.append("Call trace:")
        self.trace_check(calltrace, res)

        alloc_trace = extract_alloc_trace(self.kasan_report)
        self.report.append("\nAlloc trace:")
        self.trace_check(alloc_trace, res)

        free_trace = extract_free_trace(self.kasan_report)
        self.report.append("\nFree trace:")
        self.trace_check(free_trace, res)

        for each in res:
            if res[each]:
                return True
        return False
    
    def trace_check(self, trace, res):
        for each_line in trace:
            dbg_info = extract_debug_info(each_line)
            if dbg_info == None:
                continue
            vul_src_file = regx_get(source_file_regx, dbg_info, 0)
            if vul_src_file == None:
                raise AnalysisModuleError("Can not extract source file from \"{}\"".format(dbg_info))
            
            victim_module, dirname = self.get_victim_module(vul_src_file)
            if victim_module == None:
                return 1
            for distro in self.cfg.get_distros():
                print_pass = False
                self._cur_distro = distro
                k = self.module_check_by_config(dirname)
                if k != 'n' and not print_pass:
                    self.report.append("Check {} ---> Pass".format(vul_src_file))
                else:
                    self.logger.info("Vendor {0} does not have {1} module ({2}) enabled".format(self._cur_distro.distro_name, self.vul_module, vul_src_file))
                    self.report.append("Check {} ---> Fail on {}".format(vul_src_file, self._cur_distro.distro_name))
                    res[distro.distro_name] = False
        return
    
    def generate_report(self):
        final_report = "\n".join(self.report)
        self.logger.info(final_report)
        self._write_to(final_report, ModulesAnalysis.REPORT_NAME)
    
    def get_victim_module(self, upstream_vul_src_file):
        basename = os.path.basename(upstream_vul_src_file)
        dirname = os.path.dirname(upstream_vul_src_file)

        if regx_match(r'arch/x86', dirname):
            return None, dirname
        if basename.endswith(".h"):
            return None, dirname
        
        vul_obj = basename[:-2]
        self.vul_module = vul_obj
        return vul_obj, dirname
    
    def module_check(self, distro, upstream_vul_src_file):
        """
        0: module disable
        1: module enable by default
        2: module enable but need to be loaded
        3: module enable but must require root
        """
        victim_module, dirname = self.get_victim_module(upstream_vul_src_file)
        if victim_module == None:
            return 1
        k = self.module_check_by_config(dirname)
        if k == 'n':
            return 0
        if k == 'y':
            return 1
        if self.vul_module in distro.default_modules:
            return 1
        if self.vul_module in distro.optional_modules:
            if self.vul_module in distro.blacklist_modules:
                return 3
            return 2
        #raise AnalysisModuleError("{} didn't find in distro, should return eariler".format(self.vul_module))
        return None

    def module_check_by_config(self, dirname):
        """
        Check config for amd64 only
        """
        
        try:
            config = self._find_config_in_vendor(dirname)
            if config == None:
                # if can not find target Makefile 
                # or can not find target config in Makefile
                # return 'y'
                return 'y'
        except CannotFindConfigForObject:
            return 'n'

        vendor_config_path = os.path.join(self._cur_distro.distro_src, ".config")
        if not os.path.exists(vendor_config_path):
            raise CannotFindKernelConfig
        if self._cur_distro.distro_name not in self.config_cache:
            self.config_cache[self._cur_distro.distro_name] = {}
            with open(vendor_config_path, "r") as f:
                texts = f.readlines()
                for line in texts:
                    if line[0] == "#":
                        continue
                    try:
                        i = line.index('=')
                        self.config_cache[self._cur_distro.distro_name][line[:i]] = line[i+1:].strip()
                    except ValueError:
                        pass

        if config not in self.config_cache[self._cur_distro.distro_name] \
                or (self.config_cache[self._cur_distro.distro_name][config] == 'n'):
            return 'n'
        if config in self.config_cache[self._cur_distro.distro_name]:
            return self.config_cache[self._cur_distro.distro_name][config]
        return 'n'
    
    def check_module_privilege(self, module_name):
        """
        True: module is loadable by normal user
        False: module is loadable by only root
        """
        if module_name not in self._loadable_modules:
            return False
        if self._loadable_modules[module_name] == 'user':
            return True
        if self._loadable_modules[module_name] == 'root':
            return False
        return False
        
    
    def _build_loadable_modules(self):
        p = os.path.join(self.path_package, "resources/loadable_modules")
        with open(p, "r") as f:
            lines = f.readlines()
            for line in lines:
                if line[0] == "#" or line == "\n":
                    continue
                self._loadable_modules[line.strip()] = 'user'
        p = os.path.join(self.path_package, "resources/root_modules")
        with open(p, "r") as f:
            lines = f.readlines()
            for line in lines:
                if line[0] == "#" or line == "\n":
                    continue
                self._loadable_modules[line.strip()] = 'root'
        
    def _open_trace(self):
        trace_file = os.path.join(self.path_case, TraceAnalysis.NAME, "trace-upstream.report")
        if not os.path.exists(trace_file):
            return None
        trace = Trace(logger=self.logger, debug=self.debug, as_servicve=True)
        trace.load_tracefile(trace_file)
        try:
            trace.serialize()
        except Exception as e:
            self.logger.error("Failed to serialize trace file: {}".format(trace_file))
            self.logger.error(e)
            return None
        return trace
    
    def _find_config_in_vendor(self, dirname):
        vul_obj = self.vul_module
        while dirname != "":
            full_dirname = os.path.join(self._cur_distro.distro_src, dirname)
            makefile = os.path.join(full_dirname, "Makefile")

            self.logger.debug("Finding {} at {}".format(vul_obj, makefile))
            config = None
            if not os.path.exists(makefile):
                return None

            config = self._find_obj_in_Makefile(vul_obj, makefile)
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

    def _find_obj_in_Makefile(self, vul_obj, makefile):
        obj2config = {}
        assignment = r'=|:=|\+='
        obj_config = r'(CONFIG_\w+)'
        obj_o = r'([a-zA-Z0-9_-]+)\.o|([a-zA-Z0-9_-]+)/'

        value = None

        updated_module_name = self.vul_module

        f = open(makefile, "r")
        content = f.readlines()
        f.close()

        t = os.path.dirname(makefile)
        foler = os.path.basename(t)
        obj2config[foler] = 'y'

        for line in content:
            if line[0] == '#' or line[0] == '\n' or regx_match(r'endif', line):
                value = None
            if regx_match(assignment, line):
                updated_module_name = regx_get(r'^([a-zA-Z-_0-9]+)-.+', line, 0)
                if updated_module_name == 'obj':
                    value = 'y'
                elif updated_module_name != None:
                    try:
                        value = obj2config[updated_module_name]
                    except Exception:
                        value = None
            v = regx_get(obj_config, line, 0)
            if v != None:
                value = v
            objects = regx_getall(obj_o, line)
            for each_obj in objects:
                if  value == None:
                    break
                for e in each_obj:
                    obj2config[e] = value
                    if e == vul_obj:
                        if updated_module_name != None and updated_module_name != 'obj':
                            self.vul_module = updated_module_name
                        return value
    
    def _write_to(self, content, name):
        file_path = "{}/{}".format(self.path_case_plugin, name)
        super()._write_to(content, file_path)

