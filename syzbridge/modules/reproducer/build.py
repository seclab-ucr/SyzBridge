import os, shutil
import socket

from modules.vm.instance import VMInstance
from subprocess import Popen, PIPE, STDOUT
from infra.tool_box import *

class Build():
    def __init__(self, kernel_cfg, manager):
        self.logger = None
        self.kernel = kernel_cfg
        self.image_path = None
        self.vmlinux = None
        self.ssh_key = None
        self.distro_name = ""
        self.path_case = manager.path_case
        self.path_syzbridge = manager.path_syzbridge
        self.path_linux = None
        self.index = manager.index
        self.root_user = None
        self.normal_user = None
        self._ssh_port = None
        self._mon_port = None
        self._gdb_port = None
        self.prepare()
        self._setup()
    
    def log(self, msg):
        if self.logger != None:
            self.logger.info(msg)

    def init_logger(self, logger):
        self.logger = logger
    
    def prepare(self):
        path_image = os.path.join(self.path_case, "img")
        os.makedirs(path_image, exist_ok=True)
        if self.kernel.type == VMInstance.DISTROS:
            self.create_snapshot(self.kernel.distro_image, path_image, self.kernel.distro_name)
        if self.kernel.type == VMInstance.UPSTREAM:
            self.create_snapshot(self.kernel.distro_image, path_image, self.kernel.distro_name)
    
    def _get_unused_port(self):
        so = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        so.bind(('localhost', 0))
        _, port = so.getsockname()
        so.close()
        return port
    
    def _setup(self):
        self.normal_user = self.kernel.normal_user
        self.root_user = self.kernel.root_user
        self.vmtype = self.kernel.type
        self.ssh_port = self.kernel.ssh_port
        if self.kernel.gdb_port != None:
            self.gdb_port = self.kernel.gdb_port
        if self.kernel.mon_port != None:
            self.mon_port = self.kernel.mon_port
        if self.vmtype == VMInstance.DISTROS:
            self.image_path = "{}/img/{}-snapshot.img".format(self.path_case, self.kernel.distro_name)
            self.vmlinux = "{}/vmlinux".format(self.kernel.distro_src)
            self.ssh_key = self.kernel.ssh_key
            self.distro_name = self.kernel.distro_name
        if self.vmtype == VMInstance.UPSTREAM:
            self.image_path = "{}/img/{}-snapshot.img".format(self.path_case, self.kernel.distro_name)
            self.vmlinux = "{}/linux-upstream/vmlinux".format(self.path_case)
            self.ssh_key = self.kernel.ssh_key
            self.path_linux = "{}/linux-{}".format(self.path_case, self.kernel.distro_name)
            self.distro_name = self.kernel.distro_name

    def create_snapshot(self, src, img, image_name):
        dst = "{}/{}-snapshot.img".format(img, image_name)
        self.log("Create image {} from {}".format(dst, src))
        if os.path.isfile(dst):
            os.remove(dst)
        cmd = ["qemu-img", "create", "-f", "qcow2", "-b", src, dst]
        p = Popen(cmd, stderr=STDOUT, stdout=PIPE)
        exitcode = p.wait()
        return exitcode
    
    def _symlink(self, src, dst):
        if os.path.islink(dst):
            os.remove(dst)
        os.symlink(src, dst)
    
    @property
    def ssh_port(self):
        if self._ssh_port == None:
            return self._get_unused_port()
        return self._ssh_port
    
    @ssh_port.setter
    def ssh_port(self, port):
        self._ssh_port = port
    
    @property
    def mon_port(self):
        if self._mon_port == None:
            return self._get_unused_port()
        return self._mon_port
    
    @mon_port.setter
    def mon_port(self, port):
        self._mon_port = port
    
    @property
    def gdb_port(self):
        if self._gdb_port == None:
            return self._get_unused_port()
        return self._gdb_port
    
    @gdb_port.setter
    def gdb_port(self, port):
        self._gdb_port = port