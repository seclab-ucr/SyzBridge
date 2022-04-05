import os, shutil

from modules.vm.instance import VMInstance
from subprocess import Popen, PIPE, STDOUT
from infra.tool_box import *

class Build():
    def __init__(self, cfg, manager):
        self.cfg = cfg
        self.image_path = None
        self.vmlinux = None
        self.ssh_key = None
        self.type_name = ""
        self.path_case = manager.path_case
        self.path_syzmorph = manager.path_syzmorph
        self.path_linux = manager.path_linux
        self.index = manager.index
        self._ssh_port = None
        self._mon_port = None
        self._gdb_port = None
        self.prepare()
        self.setup()
    
    def prepare(self):
        path_image = os.path.join(self.path_case, "img")
        os.makedirs(path_image, exist_ok=True)
        if self.cfg.type == VMInstance.DISTROS:
            self.create_snapshot(self.cfg.distro_image, path_image, self.cfg.distro_name)
            self.symlink(self.cfg.ssh_key, os.path.join(path_image, "id_rsa_{}".format(self.cfg.distro_name)))
        if self.cfg.type == VMInstance.UPSTREAM:
            self.create_snapshot(self.cfg.distro_image, path_image, self.cfg.distro_name)
            self.symlink(self.cfg.ssh_key, os.path.join(path_image, "stretch.img.key"))
    
    def setup(self):
        self.vmtype = self.cfg.type
        self.ssh_port = self.cfg.ssh_port
        if self.cfg.gdb_port != None:
            self.gdb_port = self.cfg.gdb_port
        if self.cfg.mon_port != None:
            self.mon_port = self.cfg.mon_port
        if self.vmtype == VMInstance.DISTROS:
            self.image_path = "{}/img/{}-snapshot.img".format(self.path_case, self.cfg.distro_name)
            self.vmlinux = "{}/vmlinux".format(self.cfg.distro_src)
            self.ssh_key = "{}/img/id_rsa_{}".format(self.path_case, self.cfg.distro_name)
            self.type_name = self.cfg.distro_name
        if self.vmtype == VMInstance.UPSTREAM:
            self.image_path = "{}/img/{}-snapshot.img".format(self.path_case, self.cfg.distro_name)
            self.vmlinux = "{}/linux/vmlinux".format(self.path_case)
            self.ssh_key = "{}/img/stretch.img.key".format(self.path_case)
            self.type_name = self.cfg.distro_name

    def create_snapshot(self, src, img, image_name):
        dst = "{}/{}-snapshot.img".format(img, image_name)
        if os.path.isfile(dst):
            os.remove(dst)
        cmd = ["qemu-img", "create", "-f", "qcow2", "-b", src, dst]
        p = Popen(cmd, stderr=STDOUT, stdout=PIPE)
        exitcode = p.wait()
        return exitcode
    
    def symlink(self, src, dst):
        if os.path.islink(dst):
            os.remove(dst)
        os.symlink(src, dst)
    
    @property
    def ssh_port(self):
        return self._ssh_port
    
    @ssh_port.setter
    def ssh_port(self, port):
        self._ssh_port = port + self.index
    
    @property
    def mon_port(self):
        return self._mon_port
    
    @mon_port.setter
    def mon_port(self, port):
        self._mon_port = port + self.index
    
    @property
    def gdb_port(self):
        return self._gdb_port
    
    @gdb_port.setter
    def gdb_port(self, port):
        self._gdb_port = port + self.index