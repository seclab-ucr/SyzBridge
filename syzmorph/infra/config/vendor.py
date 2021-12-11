import os

from infra.error import *

class Vendor():
    def __init__(self, cfg, index=0):
        self.keys_must_have = ["vendor_image", "ssh_port", "ssh_key", "vendor_name", "vendor_code_name", "vendor_version", "type"]
        self._ssh_port = None
        self._vendor_image = None
        self._vmlinux = None
        self._ssh_key = None
        self._vendor_src = None
        self._vendor_name = None
        self._vendor_code_name = None
        self._vendor_version = None
        self._type = None
        if cfg["type"] == "distro":
            for key in self.keys_must_have:
                if key not in cfg:
                    raise ParseConfigError(key)
                setattr(self, key, cfg[key])
        if cfg["type"] == "upstream":
            for key in ["ssh_port", "ssh_key"]:
                if key not in cfg:
                    raise ParseConfigError(key)
                setattr(self, key, cfg[key])

    @property
    def type(self):
        return self._type
    
    @type.setter
    def type(self, value):
        if value == "distro":
            self._type = 0
            return
        if value == "upstream":
            self._type = 1
            return
        raise KernelTypeError(value)

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
    
    @property
    def vendor_code_name(self):
        return self._vendor_code_name
    
    @vendor_code_name.setter
    def vendor_code_name(self, n):
        if type(n) != str:
            raise TargetFormatNotMatch(n, type(n), str)
        self._vendor_code_name = n

    @property
    def vendor_version(self):
        return self._vendor_version
    
    @vendor_version.setter
    def vendor_version(self, n):
        if type(n) != str:
            raise TargetFormatNotMatch(n, type(n), str)
        self._vendor_version = n