import os, json
import logging
import importlib

from infra.error import *
from syzmorph.modules.vm.instance import VMInstance
from .vendor import Vendor
from infra.tool_box import *

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
        i = 0
        kernel_cfg = cfg['kernel']
        for vendor in kernel_cfg:
            vend_cfg = kernel_cfg[vendor]
            _cfg = Vendor(vend_cfg, i)
            setattr(self.kernel, vendor, _cfg)
            i += 1

        proj_dir = os.path.join(os.getcwd(), "syzmorph")
        modules_dir = os.path.join(proj_dir, "plugins")
        module_folder = [ cmd for cmd in os.listdir(modules_dir)
                    if not cmd.endswith('.py') and not cmd == "__pycache__" ]
        for module_name in module_folder:
            try:
                module = importlib.import_module("plugins.{}".format(module_name))
                class_name = convert_folder_name_to_plugin_name(module_name)
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

    def get_all_kernels(self):
        res = []
        for name in self.kernel.__dict__:
            cfg = getattr(self.kernel, name)
            res.append(cfg)
        return res

    def get_distros(self):
        res = []
        for name in self.kernel.__dict__:
            distro = getattr(self.kernel, name)
            if distro.type == VMInstance.DISTROS:
                res.append(distro)
        return res
    
    def get_upstream(self):
        for name in self.kernel.__dict__:
            distro = getattr(self.kernel, name)
            if distro.type == VMInstance.UPSTREAM:
                return distro
        return None
    
    def get_plugin(self, name):
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