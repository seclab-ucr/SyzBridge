import os, json

from infra.error import *
from infra.tool_box import *
from modules.reproducer import Reproducer

class Vendor():
    def __init__(self, cfg, index=0):
        self.keys_must_have = ["distro_image", "ssh_port", "ssh_key", "distro_name", "distro_code_name", "distro_version", "distro_src", "type"]
        self.default_modules = {}
        self.optional_modules = {}
        self.blacklist_modules = {}
        self._ssh_port = None
        self._gdb_port = None
        self._mon_port = None
        self._distro_image = None
        self._vmlinux = None
        self._ssh_key = None
        self._vendor_src = None
        self._distro_name = None
        self._distro_code_name = None
        self._distro_version = None
        self._built_modules = False
        self._type = None
        self._repro = None
        if cfg["type"] == "distro":
            for key in self.keys_must_have:
                if key not in cfg:
                    raise ParseConfigError(key)
        if cfg["type"] == "upstream":
            for key in ["ssh_port", "ssh_key", "type", "distro_image", "distro_name"]:
                if key not in cfg:
                    raise ParseConfigError(key)
        for key in cfg:
            setattr(self, key, cfg[key])
    
    def build_module_list(self):
        if self._built_modules:
            return
        self._built_modules = True
        if self._read_modules_from_cache():
            return
        qemu = self.repro.launch_qemu()
        _, queue = self.repro.run_qemu(qemu, self._get_modules)
        queue.get(block=True)
        qemu.kill()
        self._dump_modules_to_cache()
    
    def _read_modules_from_cache(self):
        for name in ["optional_modules", "default_modules", "blacklist_modules"]:
            cache_file = os.path.join(self.distro_src, name+".json")
            if not os.path.exists(cache_file):
                return False
            setattr(self, name, json.load(open(cache_file, "r")))
        return True
    
    def _dump_modules_to_cache(self):
        for name in ["optional_modules", "default_modules", "blacklist_modules"]:
            cache_file = os.path.join(self.distro_src, name+".json")
            json.dump(getattr(self, name), open(cache_file, "w"))
    
    def _get_modules(self, qemu):
        for each in self._get_optional_modules(qemu):
            self.optional_modules[each] = True
        for each in self._get_default_modules(qemu):
            self.default_modules[each] = True
        for each in self._get_blacklist_modules(qemu):
            self.blacklist_modules[each] = True
        qemu.alternative_func_output.put("done")
    
    def _get_default_modules(self, qemu):
        res = []
        module_regx = r'^([a-zA-Z-_0-9]+)'
        output = qemu.command(cmds="lsmod", user="root", wait=True)
        for each in output[2:]:
            name = regx_get(module_regx, each, 0)
            if name == None:
                continue
            res.append(name)
        return res

    def _get_optional_modules(self, qemu):
        res = []
        module_regx = r'([a-zA-Z-_0-9]+)\.ko'
        output = qemu.command(cmds="find /lib/modules/$(uname -r) -type f -name '*.ko*'", user="root", wait=True)
        for each in output:
            name = regx_get(module_regx, each, 0)
            if name == None:
                continue
            res.append(name)
        return res
    
    def _get_blacklist_modules(self, qemu):
        res = []
        blacklist_regx = r'^blacklist ([a-zA-Z-_0-9]+)'
        alias_regx = r'^alias ([a-zA-Z-_0-9]+) off'
        output = qemu.command(cmds="cat /etc/modprobe.d/*.conf", user="root", wait=True)
        for each in output:
            name = regx_get(blacklist_regx, each, 0)
            if name is None:
                name = regx_get(alias_regx, each, 0)
                if name is None:
                    continue
            if not name in self.optional_modules:
                name = self._convert_alias_module(qemu, name)
                if not name in self.optional_modules:
                    continue
            res.append(name)
        return res
    
    def _convert_alias_module(self, qemu, module):
        output = qemu.command(cmds="modinfo {}".format(module), user="root", wait=True)
        module_regx = r'([a-zA-Z-_0-9]+)\.ko'
        for each in output:
            if regx_match(r'^filename', each):
                name = regx_get(module_regx, each, 0)
                return name
        return ""

    @property
    def repro(self):
        return self._repro
    
    @repro.setter
    def repro(self, value):
        if not isinstance(value, Reproducer):
            raise TypeError("repro must be an instance of Reproducer")
        self._repro = value

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
    def distro_image(self):
        return self._distro_image
    
    @distro_image.setter
    def distro_image(self, image):
        if not os.path.exists(image):
            raise TargetFileNotExist(image)
        self._distro_image = image
    
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
    def distro_src(self):
        return self._vendor_src
    
    @distro_src.setter
    def distro_src(self, value):
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
    def gdb_port(self):
        return self._gdb_port
    
    @gdb_port.setter
    def gdb_port(self, n):
        if type(n) != int:
            raise TargetFormatNotMatch(n, type(n), int)
        self._gdb_port = n

    @property
    def mon_port(self):
        return self._mon_port
    
    @mon_port.setter
    def mon_port(self, n):
        if type(n) != int:
            raise TargetFormatNotMatch(n, type(n), int)
        self._mon_port = n

    @property
    def distro_name(self):
        return self._distro_name
    
    @distro_name.setter
    def distro_name(self, n):
        if type(n) != str:
            raise TargetFormatNotMatch(n, type(n), str)
        self._distro_name = n
    
    @property
    def distro_code_name(self):
        return self._distro_code_name
    
    @distro_code_name.setter
    def distro_code_name(self, n):
        if type(n) != str:
            raise TargetFormatNotMatch(n, type(n), str)
        self._distro_code_name = n

    @property
    def distro_version(self):
        return self._distro_version
    
    @distro_version.setter
    def distro_version(self, n):
        if type(n) != str:
            raise TargetFormatNotMatch(n, type(n), str)
        self._distro_version = n