import os, json

from .error import *

base_ssh_port = 36777

class Config:
    def __init__(self) -> None:
        self.keys_list = ["vendor_image", "vmlinux", "max_retrieval", "max_parallel", "ssh_port", "ssh_key", "vendor_src", "vendor_name"]
        self._ssh_port = base_ssh_port

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
                self.load(cfg)
        else:
            print("Cannot find config file: {}".format(config))
    
    def load(self, cfg):
        for key in cfg:
            if key not in self.keys_list:
                raise ParseConfigError(key)
            setattr(self, key, cfg[key])
        return cfg

    @property
    def vendor_image(self):
        return self._vendor_image
    
    @vendor_image.setter
    def vendor_image(self, image):
        if not os.path.exists(image):
            raise TargetFileNotExist(image)
        self._vendor_image = image
    
    @property
    def vmlinux(self):
        return self._vmlinux
    
    @vmlinux.setter
    def vmlinux(self, vmx):
        if not os.path.exists(vmx):
            raise TargetFileNotExist(vmx)
        self._vmlinux = vmx
    
    @property
    def ssh_key(self):
        return self._ssh_key
    
    @ssh_key.setter
    def ssh_key(self, value):
        if not os.path.exists(value):
            raise TargetFileNotExist(value)
        self._ssh_key = value
    
    @property
    def upstream_src(self):
        return self._upstream_src
    
    @upstream_src.setter
    def upstream_src(self, value):
        if not os.path.exists(value):
            raise TargetFileNotExist(value)
        self._upstream_src = value
    
    @property
    def vendor_src(self):
        return self._vendor_src
    
    @vendor_src.setter
    def vendor_src(self, value):
        if not os.path.exists(value):
            raise TargetFileNotExist(value)
        self._vendor_src = value
    
    @property
    def max_retrieval(self):
        return self._max_retrieval
    
    @max_retrieval.setter
    def max_retrieval(self, n):
        if type(n) != int:
            raise TargetFormatNotMatch(n, type(n), int)
        self._max_retrieval = n

    @property
    def max_parallel(self):
        return self._max_parallel
    
    @max_parallel.setter
    def max_parallel(self, n):
        if type(n) != int:
            raise TargetFormatNotMatch(n, type(n), int)
        self._max_parallel = n
    
    @property
    def ssh_port(self):
        return self._ssh_port
    
    @ssh_port.setter
    def ssh_port(self, n):
        if type(n) != int:
            raise TargetFormatNotMatch(n, type(n), int)
        self._ssh_port = n

    @property
    def vendor_name(self):
        return self._vendor_name
    
    @vendor_name.setter
    def vendor_name(self, n):
        if type(n) != str:
            raise TargetFormatNotMatch(n, type(n), str)
        self._vendor_name = n