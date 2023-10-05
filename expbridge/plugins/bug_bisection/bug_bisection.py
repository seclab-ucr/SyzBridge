from ast import Import
import os, logging
import shutil
import threading
import queue

from modules.vm import VM
from infra.tool_box import *
from plugins import AnalysisModule
from plugins.syzkaller_interface import SyzkallerInterface

qemu_output_window = 15

class BugBisection(AnalysisModule):
    NAME = "BugBisection"
    REPORT_START = "======================BugBisection Report======================"
    REPORT_END =   "==================================================================="
    REPORT_NAME = "Report_BugBisection"
    DEPENDENCY_PLUGINS = []

    def __init__(self):
        super().__init__()
        
    def prepare(self):
        plugin = self.cfg.get_plugin(self.NAME)
        if plugin == None:
            self.err_msg("No such plugin {}".format(self.NAME))
        try:
            self.repro_timeout = int(plugin.timeout)
        except AttributeError:
            self.err_msg("Failed to get timeout")
            return False
        try:
            self.repro_attempt = int(plugin.attempt)
        except AttributeError:
            self.repro_attempt = 3
        try:
            self.kernel_version = plugin.kernel_version
        except AttributeError:
            return False
        return self.prepare_on_demand()
    
    def prepare_on_demand(self):
        self._prepared = True
        return True
    
    def success(self):
        return self._move_to_success
    
    def build_upstream_kernel(self, kernel_version):
        #if self._check_stamp("BUILD_KERNEL"):
        #    self._remove_stamp("BUILD_KERNEL")
        ret = self.build_mainline_kernel(commit=kernel_version, keep_ori_config=True)
        if ret == 0:
            self._create_stamp("BUILD_SYZ_FEATURE_MINIMIZE_KERNEL")
        return ret

    def run(self):
        i386 = False
        if regx_match(r'386', self.case["manager"]):
            i386 = True
        for version in self.kernel_version[self.case_hash]:
            self.logger.info("Now testing {}".format(version))
            if self.build_upstream_kernel(kernel_version=version) != 0:
                self.err_msg("Failed to build upstream kernel")
                return False
            if not self.test_poc(i386=i386, version=version):
                self.report.append("Bug doesn't reproduce on {}".format(version))
                return True
            self.report.append("Bug triggered on {}".format(version))
        return False

    def test_poc(self, i386, version):
        upstream = self.cfg.get_kernel_by_name(self.kernel)
        if upstream == None:
            self.logger.exception("Fail to get {} kernel".format(self.kernel))
            return False
        upstream.repro.init_logger(self.logger)
        _, triggered, _ = upstream.repro.reproduce(func=self._capture_crash, func_args=(i386,), vm_tag='test {}'.format(version),\
            timeout=self.repro_timeout + 100, attempt=self.repro_attempt, root=True, work_dir=self.path_case_plugin, c_hash=self.case_hash)
        self.info_msg("crash triggered: {}".format(triggered))
        return triggered

    def _capture_crash(self, qemu: VM, root: bool, i386: bool):
        qemu.upload(user='root', src=["{}/poc.c".format(self.path_case_plugin)], dst="~/poc.c", wait=True)
        if i386:
            qemu.command(cmds="gcc -m32 -pthread -o poc poc.c", user="root", wait=True)
        else:
            qemu.command(cmds="gcc -pthread -o poc poc.c", user="root", wait=True)
        
        qemu.command(cmds="./poc", user="root", wait=True, timeout=self.repro_timeout)
        return

    def generate_report(self):
        final_report = "\n".join(self.report)
        self.info_msg(final_report)
        self._write_to(final_report, self.REPORT_NAME)
    
    def _write_to(self, content, name):
        file_path = "{}/{}".format(self.path_case_plugin, name)
        super()._write_to(content, file_path)

    def cleanup(self):
        super().cleanup()