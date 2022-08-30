import os, json
import logging
import importlib

from infra.error import *
from syzmorph.modules.vm.instance import VMInstance
from .vendor import Vendor
from infra.tool_box import *
from typing import List

base_ssh_port = 36777

logger = logging.getLogger(__name__)

class Kernel():
    def __init__(self):
        pass

class Plugin():
    def __init__(self):
        pass

class Config:
    def __init__(self):
        self.kernel = Kernel()
        self.plugin = Plugin()

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
        kernel_cfg = cfg['kernel']
        t = {}
        for vendor in kernel_cfg:
            vend_cfg = kernel_cfg[vendor]
            _cfg = Vendor(vend_cfg)
            if _cfg.distro_name not in t:
                setattr(self.kernel, vendor.lower(), _cfg)
                t[_cfg.distro_name] = True
            else:
                raise DuplicatedDistro(_cfg.distro_name)

        proj_dir = os.path.join(os.getcwd(), "syzmorph")
        modules_dir = os.path.join(proj_dir, "plugins")
        module_folder = [ cmd for cmd in os.listdir(modules_dir)
                    if not cmd.endswith('.py') and not cmd == "__pycache__" ]
        for module_name in module_folder:
            try:
                module = importlib.import_module("plugins.{}".format(module_name))
                setattr(module, "dependency", "strong")
                class_name = convert_folder_name_to_plugin_name(module_name)
                new_class = getattr(module, class_name)
                setattr(module, 'instance', new_class())
                setattr(self.plugin, class_name, module)
            except Exception as e:
                print("Fail to load plugin {}: {}".format(module_name, e))
                continue
        plugin_cfg = cfg['plugin']
        for plugin in plugin_cfg:
            module = getattr(self.plugin, plugin)
            for key in plugin_cfg[plugin]:
                setattr(module, key, plugin_cfg[plugin][key])
        return cfg

    def get_all_kernels(self) -> List[Vendor]:
        res = []
        for name in self.kernel.__dict__:
            cfg = getattr(self.kernel, name)
            res.append(cfg)
        return res

    def get_distro_by_name(self, name):
        distro = getattr(self.kernel, name)
        if distro.type == VMInstance.DISTROS:
            return distro
        return None
    
    # get_all_distros ignore is_inited() and need_repro()
    # It returns every distro that was defined in config file
    def get_all_distros(self)-> List[Vendor]:
        res = []
        for name in self.kernel.__dict__:
            distro = getattr(self.kernel, name)
            if distro.type == VMInstance.DISTROS:
                res.append(distro)
        return res

    def get_distros(self)-> List[Vendor]:
        res = []
        for name in self.kernel.__dict__:
            distro = getattr(self.kernel, name)
            if distro.type == VMInstance.DISTROS:
                if not distro.is_inited():
                    continue
                if not distro.repro.need_repro():
                    continue
                res.append(distro)
        return res
    
    def get_upstream(self)-> Vendor:
        for name in self.kernel.__dict__:
            distro = getattr(self.kernel, name)
            if distro.type == VMInstance.UPSTREAM:
                return distro
        return None
    
    def get_plugin(self, name)-> Plugin:
        try:
            plugin = getattr(self.plugin, name)
        except:
            return None
        return plugin
    
    def is_plugin_enabled(self, name):
        try:
            plugin = getattr(self.plugin, name)
        except:
            return False
        return plugin.ENABLE
    
    def is_plugin_service(self, name):
        try:
            plugin = getattr(self.plugin, name)
        except:
            return False
        return plugin.AS_SERVICE