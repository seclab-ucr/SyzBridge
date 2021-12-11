import os, json
import logging

from infra.error import *
from syzmorph.modules.vm.instance import VMInstance
from .vendor import Vendor

base_ssh_port = 36777

logger = logging.getLogger(__name__)

class Config:
    def __init__(self):
        pass

    def load_from_file(self, config):
        work_path = os.getcwd()
        if not os.path.exists(config):
            config_path = os.path.join(work_path, config)
        else:
            config_path = config
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                cfg = json.load(f)
                f.close()
                return self.load(cfg)
        else:
            raise TargetFileNotExist(config)
    
    def load(self, cfg):
        i = 0
        for vendor in cfg:
            vend_cfg = cfg[vendor]
            _cfg = Vendor(vend_cfg, i)
            setattr(self, vendor, _cfg)
            i += 1
        return cfg

    def get_distros(self):
        res = []
        for name in self.__dict__:
            distro = getattr(self, name)
            if distro.type == VMInstance.DISTROS:
                res.append(distro)
        return res
    
    def get_upstream(self):
        res = []
        for name in self.__dict__:
            distro = getattr(self, name)
            if distro.type == VMInstance.UPSTREAM:
                res.append(distro)
        return res