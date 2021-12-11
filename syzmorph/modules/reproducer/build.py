import os, shutil

from modules.vm.instance import VMInstance
from subprocess import Popen, PIPE, STDOUT
from infra.tool_box import *

class Build():
    def __init__(self, cfg, path_case, path_syzmorph, path_linux):
        self.image_path = None
        self.vmlinux = None
        self.ssh_key = None
        self.ssh_port = None
        self.type_name = ""
        self.path_case = path_case
        self.path_syzmorph = path_syzmorph
        self.path_linux = path_linux
        for distro in cfg.get_distros():
            self.prepare(distro)
    
    def prepare(self, cfg):
        path_image = os.path.join(self.path_case, "img")
        os.makedirs(path_image, exist_ok=True)
        if cfg.type == VMInstance.DISTROS:
            self.create_snapshot(cfg.vendor_image, path_image, cfg.vendor_name)
            self.symlink(cfg.ssh_key, os.path.join(path_image, "id_rsa_{}".format(cfg.vendor_name)))
        if cfg.type == VMInstance.UPSTREAM:
            self.symlink(cfg.vendor_image, os.path.join(path_image, "stretch.img"))
            self.symlink(cfg.ssh_key, os.path.join(path_image, "stretch.img.key"))
    
    def setup(self, cfg):
        self.vmtype = cfg.type
        self.ssh_port = cfg.ssh_port
        if self.vmtype == VMInstance.DISTROS:
            self.image_path = "{}/img/{}-snapshot.img".format(self.path_case, cfg.vendor_name)
            self.vmlinux = "{}/vmlinux".format(self.path_case)
            self.ssh_key = "{}/img/id_rsa_{}".format(self.path_case, cfg.vendor_name)
            self.type_name = cfg.vendor_name
        if self.vmtype == VMInstance.UPSTREAM:
            self.image_path = "{}/img/stretch.img".format(self.path_case)
            self.vmlinux = "{}/vmlinux".format(self.path_case)
            self.ssh_key = "{}/img/stretch.img.key".format(self.path_case)
            self.type_name = "upstream"

    def create_snapshot(self, src, img, vendor_name):
        dst = "{}/{}-snapshot.img".format(img, vendor_name)
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