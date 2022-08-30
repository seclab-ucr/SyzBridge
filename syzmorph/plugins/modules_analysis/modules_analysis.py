from distutils import extension
import os, random
from posixpath import basename, dirname

from infra.tool_box import *
from infra.strings import source_file_regx
from plugins import AnalysisModule
from plugins.error import *
from plugins.trace_analysis import TraceAnalysis
from infra.ftraceparser.ftraceparser.trace import Trace
from modules.vm import VM, VMInstance
from syzmorph.infra.config.vendor import Vendor

class TraceAnalysisError(Exception):
    pass
class ModulesAnalysis(AnalysisModule):
    NAME = "ModulesAnalysis"
    REPORT_START = "======================Modules Analysis Report======================"
    REPORT_END =   "==================================================================="
    REPORT_NAME = "Report_ModulesAnalysis"
    DEPENDENCY_PLUGINS = ["TraceAnalysis"]
    MODULE_DISABLED = 0
    MODULE_ENABLED = 1
    MODULE_REQUIRED_LOADING = 2
    MODULE_IN_BLACKLIST = 3
    MODULE_REQUIRED_LOADING_BY_ROOT = 4
    MODULE_REQUIRED_LOADING_BY_NON_ROOT = 5

    def __init__(self):
        super().__init__()
        self.kasan_report = None
        self.config_cache = {}
        self._remove_trace_file = False

        self.vul_module = None
        self.cfg = None
        self._cur_distro: Vendor = None
        self.config_cache['vendor_config_path'] = ''
        self._loadable_modules = {}
        self._ftrace_functions = {}
        self.vm = {}
    
    def check(func):
        def inner(self):
            ret = func(self)
            if ret:
                self.main_logger.info("[Modules analysis] Modules analysis passed")
            else:
                self.main_logger.info("[Modules analysis] Failed to analyze modules")
            return ret
        return inner
    
    def prepare(self):
        try:
            plugin = self.cfg.get_plugin(self.NAME)
            if plugin == None:
                self.err_msg("No such plugin {}".format(self.NAME))
            remove_trace_file = plugin.remove_trace_file
        except AttributeError:
            remove_trace_file = False
        report = request_get(self.case['report'])
        self._build_loadable_modules()
        return self.prepare_on_demand(report.text, remove_trace_file)
    
    def prepare_on_demand(self, report, remove_trace_file):
        self._prepared = True
        self._remove_trace_file = remove_trace_file
        self.kasan_report = report.split('\n')
        if self.kasan_report == []:
            return False
        return True
    
    def success(self):
        return self._move_to_success

    @check
    def run(self):
        if not self._prepared:
            self.err_msg("Module {} is not prepared".format(ModulesAnalysis.NAME))
            return False
        self.report.append(ModulesAnalysis.REPORT_START)

        #self.logger.info("[Modules analysis] Checking modules in KASAN report")
        #self.check_kasan_report()
        #self.logger.info("[Modules analysis] Checking modules in ftrace")
        try:
            self.check_ftrace()
        except TraceAnalysisError as e:
            self.err_msg("[Modules analysis] {}".format(e))
            self.main_logger.error("[Modules analysis] {}".format(e))
            return False
                
        self.report.append(ModulesAnalysis.REPORT_END)
        if self._remove_trace_file:
            self.remove_trace_file()
        self.set_stage_text("Done")
        return True
    
    def remove_trace_file(self):
        for file in os.listdir(self.path_case_plugin):
            if file.endswith('.report'):
                try:
                    os.remove(os.path.join(self.path_case_plugin, file))
                except:
                    pass

    def check_ftrace(self):
        trace = self._open_trace()
        if trace == None:
            raise TraceAnalysisError("Failed to open upstream trace file")
        check_map = {}
        all_distros = self.cfg.get_distros()
        for distro in all_distros:
            distro.build_module_list()
            check_map[distro.distro_name] = {}
            self.vm[distro.distro_name] = self._prepare_gdb(distro)

        trace.add_filter("task", "==\"poc\"")
        begin_node = trace.find_node(0)
        while begin_node != None:
            if begin_node.parent is None and begin_node.is_function and not trace.is_filtered(begin_node):
                self.set_stage_text("Checking {}".format(begin_node.function_name))
                if all_distros == []:
                    return False
                self.info_msg("Starting from node {}".format(begin_node.info))
                if not self.check_modules_in_trace(begin_node, check_map, all_distros):
                    return False
            begin_node = begin_node.next_node_by_time
        return True
    
    def check_modules_in_trace(self, begin_node, check_map, all_distros):
        end_node = begin_node.scope_end_node
        hook_end_node = None
        while begin_node != end_node:
            # To matain a one time loop, we can procceed to next node by 'break'
            # next node will be found after the loop
            for _ in range(0, 1):
                if begin_node.is_function:
                    if hook_end_node == None:
                        hook_end_node = self.is_hook_func(begin_node)
                    for distro in all_distros:
                        self._cur_distro = distro
                        src_file, procceed = self.get_src_file_from_function(begin_node, distro)
                        if src_file == None:
                            continue
                        if procceed:
                            if src_file in check_map[distro.distro_name]:
                                continue
                            if self._is_generic_module(src_file):
                                continue
                            check_map[distro.distro_name][src_file] = True
                            ret = self.module_check(distro, src_file)
                            self.info_msg("Module {} in {} {}".format(self.vul_module, distro.distro_name, ret))
                            if ret == None or ret == self.MODULE_ENABLED:
                                continue
                            if self.vul_module not in self.results:
                                self.results[self.vul_module] = {'name': self.vul_module, 'src_file': src_file, 'hook': hook_end_node != None, 'missing': {}}
                            miss_info = {'distro_name': distro.distro_name, 'distro_version': distro.distro_version}
                            if ret == self.MODULE_DISABLED:
                                miss_info['type'] = self.MODULE_DISABLED
                                miss_info['missing_reason'] = 'Module disabled'
                                self.report.append(begin_node.text)
                                self.info_msg("Vendor {0} does not have {1} module enabled".format(distro.distro_name, self.vul_module))
                                self.report.append("[Disabled] Module {} from {} is not enabled in {}".format(self.vul_module, src_file, distro.distro_name))
                            if ret == self.MODULE_REQUIRED_LOADING:
                                miss_info['type'] = self.MODULE_REQUIRED_LOADING_BY_ROOT
                                miss_info['missing_reason'] = 'need loading by root'
                                self.report.append(begin_node.text)
                                user = 'root'
                                if self.check_module_privilege(self.vul_module):
                                    miss_info['type'] = self.MODULE_REQUIRED_LOADING_BY_NON_ROOT
                                    miss_info['missing_reason'] = 'need loading by normal user'
                                    user = 'normal user'
                                self.report.append("[{}] Module {} from {} need to be loaded in {} ".format(user, self.vul_module, src_file, distro.distro_name))
                            if ret == self.MODULE_IN_BLACKLIST:
                                miss_info['type'] = self.MODULE_IN_BLACKLIST
                                miss_info['missing_reason'] = 'Module in blacklist'
                                self.report.append(begin_node.text)
                                self.report.append("[Blacklist] Module {} from {} need root to be loaded".format(self.vul_module, src_file))
                            self.results[self.vul_module]['missing'][distro.distro_name] = miss_info
            begin_node = begin_node.next_node
            if hook_end_node == begin_node:
                hook_end_node = None
        return True
    
    def is_hook_func(self, node):
        # hook functions often link to unnecessary code in terms of bug's root cause
        if 'hook' in node.function_name:
            return node.scope_end_node
        return None
    
    def get_src_file_from_function(self, begin_node, distro: Vendor):
        if distro.distro_name not in self._ftrace_functions:
            self._ftrace_functions[distro.distro_name] = {}
        if begin_node.function_name in self._ftrace_functions[distro.distro_name]:
            return self._ftrace_functions[distro.distro_name][begin_node.function_name], False
        addr = self.vm[distro.distro_name].get_func_addr(begin_node.function_name)
        if addr == 0:
            self.debug_msg("Function {} doesn't have symbol file".format(begin_node.function_name))
            self._ftrace_functions[distro.distro_name][begin_node.function_name] = None
            return None, False
        file, _ = self.vm[distro.distro_name].get_dbg_info(addr)
        self._ftrace_functions[distro.distro_name][begin_node.function_name] = file
        return file, True
        
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
                    self.info_msg("Vendor {0} does not have {1} module ({2}) enabled".format(self._cur_distro.distro_name, self.vul_module, vul_src_file))
                    self.report.append("Check {} ---> Fail on {}".format(vul_src_file, self._cur_distro.distro_name))
                    res[distro.distro_name] = False
        return
    
    def generate_report(self):
        final_report = "\n".join(self.report)
        self.info_msg(final_report)
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
        victim_module, dirname = self.get_victim_module(upstream_vul_src_file)
        if victim_module == None:
            return self.MODULE_ENABLED
        k = self.module_check_by_config(dirname) # victim_module pass to self.vul_module, this function actually check the vul module
        if k == 'n':
            return self.MODULE_DISABLED
        if k == 'y':
            return self.MODULE_ENABLED
        if self.vul_module in distro.default_modules:
            return self.MODULE_ENABLED
        if self.vul_module in distro.optional_modules:
            if self.vul_module in distro.blacklist_modules:
                return self.MODULE_IN_BLACKLIST
            return self.MODULE_REQUIRED_LOADING
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

        vendor_config_path = os.path.join(self._cur_distro.distro_src, "config")
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
    
    def set_history_status(self):
        if self.results == {}:
            self.set_stage_text("Failed")
            return
        self.set_stage_text("Done")
        return
    
    def _prepare_gdb(self, distro: Vendor):
        vmlinux = distro.repro.vmlinux
        image = distro.repro.image_path
        key = distro.repro.ssh_key
        vm = VM(linux=distro.distro_src, cfg=distro, vmlinux=vmlinux, key=key,
            port=random.randint(1024, 65535), image=image, hash_tag=self.case_hash)
        vm.gdb_attach_vmlinux()
        self._gdb_load_all_modules(distro, vm)
        return vm
    
    def _gdb_load_all_modules(self, distro: Vendor, vm: VM):
        dirname = os.path.dirname(distro.distro_src)
        modules_dir = os.path.join(dirname, 'modules')
        out = local_command("find {} -name \"*.ko\"".format(modules_dir), shell=True)
        base_addr = 0x10000000
        for each_module in out:
            each_module = each_module.strip()
            if os.path.exists(each_module):
                offset = self._get_module_offset(each_module)
                size = self._get_module_size(each_module)
                self.debug_msg("Loading {} into gdb at {}".format(each_module, hex(base_addr)))
                vm.gdb.add_symbol_file(each_module, base_addr)
                if offset != None and size != None:
                    base_addr += self._round_up(size + offset)
    
    def _round_up(self, value):
        align = 1
        while value > (align << 4):
            align = align << 4
        return (value + align - 1) & ~(align - 1)
    
    def _get_module_offset(self, module_path):
        ret = 0
        out = local_command("readelf -WS {} | grep -E \" \.text \" | awk '{{ print \"0x\"$6 }}'".format(module_path), shell=True)
        try:
            ret = int(out[0], 16)
        except:
            return None
        return ret
    
    def _get_module_size(self, module_path):
        ret = 0
        out = local_command("readelf -WS {} | grep -E \" \.text \" | awk '{{ print \"0x\"$7 }}'".format(module_path), shell=True)
        try:
            ret = int(out[0], 16)
        except:
            return None
        return ret

    def _is_generic_module(self, src):
        if self._base_dir(src) == "mm":
            """
            If moduels are in mm/, we ignore them because different allocators 
            usually don't make any differences
            """
            return True
        if self._base_dir(src) == "security":
            """
            Bugs are usually not in the security policies modules
            """
            return True
        if src == "kernel/kcov.c":
            """
            kcov collect coverage, not the root cause of any bugs.
            """
            return True
        return False
    
    def _base_dir(self, src):
        try:
            i = src.index('/')
            return src[:i]
        except Exception:
            return None
    
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
        self.info_msg("Open trace file: {}".format(trace_file))

        self.set_stage_text("Loading trace-upstream.report")
        trace = Trace(logger=self.logger, debug=self.debug, as_servicve=True)
        trace.load_tracefile(trace_file)
        try:
            trace.serialize()
        except Exception as e:
            self.err_msg("Failed to serialize trace file {}: {}".format(trace_file, e))
            return None
        return trace
    
    def _find_config_in_vendor(self, dirname):
        vul_obj = self.vul_module
        while dirname != "":
            full_dirname = os.path.join(self._cur_distro.distro_src, dirname)
            makefile = os.path.join(full_dirname, "Makefile")

            self.debug_msg("Finding {} at {}".format(vul_obj, makefile))
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
                self.debug_msg("{} was enabled by obj-y. Go to the outer Makefile".format(vul_obj))
                vul_obj = os.path.basename(dirname)
                dirname = os.path.dirname(dirname)
            else:
                self.debug_msg("Matching config {}".format(config))
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
        comeback = False

        for i in range(0, 2):
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
                            comeback = True
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
            if not comeback:
                break
    
    def _write_to(self, content, name):
        file_path = "{}/{}".format(self.path_case_plugin, name)
        super()._write_to(content, file_path)

    def cleanup(self):
        super().cleanup()
