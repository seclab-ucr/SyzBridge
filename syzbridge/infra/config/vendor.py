import os, json
import socket

from infra.error import *
from infra.tool_box import *
from modules.reproducer import Reproducer

class Vendor():
    def __init__(self, cfg):
        self.keys_must_have = ["distro_image", "ssh_key", "distro_name", "distro_code_name", "distro_version", "type", "root_user", "normal_user"]
        self.default_modules = {}
        self.optional_modules = {}
        self.blacklist_modules = {}
        self.func2module = {}
        self._root_user = None
        self._normal_user = None
        self._ssh_port = None
        self._gdb_port = None
        self._mon_port = None
        self._distro_image = None
        self._vmlinux = None
        self._exclude = []
        self._include = []
        self._ssh_key = None
        self._vendor_src = None
        self._distro_name = None
        self._distro_code_name = None
        self._distro_version = None
        self._effective_cycle_start = ""
        self._effective_cycle_end = ""
        self._built_modules = False
        self._type = None
        self._repro = None
        self._init = False
        if cfg["type"] == "distro":
            for key in self.keys_must_have:
                if key not in cfg:
                    raise ParseConfigError(key)
        if cfg["type"] == "upstream":
            for key in ["ssh_key", "type", "distro_image", "distro_name"]:
                if key not in cfg:
                    raise ParseConfigError(key)
        if cfg["type"] == "android":
            for key in ["distro_image", "distro_name", "cross_compiler"]:
                if key not in cfg:
                    raise ParseConfigError(key)
        for key in cfg:
            setattr(self, key, cfg[key])
    
    def build_module_list(self, vm_tag='', work_path="/tmp"):
        if self._built_modules:
            return
        self._built_modules = True
        if self._read_modules_from_cache():
            return
        qemu = self.repro.launch_qemu(tag=vm_tag, work_path=work_path)
        self.repro.run_qemu(qemu, self._get_modules)
        qemu.wait()
        qemu.destroy()
        self.build_module_func_list()
        self._dump_modules_to_cache()
    
    def build_module_func_list(self):
        file_path_regex = r'File: (.*\.ko)'
        cmd = "readelf -sW vmlinux | awk '{{ if ($4 == \"FUNC\") print $8; else if ($1 ~ /File:/) print}}'"
        out = local_command(cmd, shell=True, cwd=self.distro_src)
        cur_module = "vmlinux"
        for func in out:
            func = func.strip()
            if func not in self.func2module:
                self.func2module[func] = []
            if cur_module not in self.func2module[func]:
                self.func2module[func].append(cur_module) 

        dirname = os.path.dirname(self.distro_src)
        modules_dir = os.path.join(dirname, 'modules')
        cmd = "readelf -sW `find ./ -name \"*.ko\"` | awk '{{ if ($4 == \"FUNC\") print $8; else if ($1 ~ /File:/) print}}'"
        out = local_command(cmd, shell=True, cwd=modules_dir)
        for func in out:
            func = func.strip()
            if regx_match(r'^File:', func):
                cur_module = regx_get(file_path_regex, func, 0)
                if cur_module.startswith("./"):
                    cur_module = cur_module[2:]
                continue
            if func not in self.func2module:
                self.func2module[func] = []
            if cur_module not in self.func2module[func]:
                self.func2module[func].append(cur_module)
        return

    def is_inited(self):
        return self._init
    
    def _read_modules_from_cache(self):
        for name in ["optional_modules", "default_modules", "blacklist_modules", "func2module"]:
            cache_file = os.path.join(self.distro_src, name+".json")
            if not os.path.exists(cache_file):
                return False
            data = json.load(open(cache_file, "r"))
            setattr(self, name, data)
            if data == {}:
                return False
        return True
    
    def _dump_modules_to_cache(self):
        for name in ["optional_modules", "default_modules", "blacklist_modules", "func2module"]:
            cache_file = os.path.join(self.distro_src, name+".json")
            json.dump(getattr(self, name), open(cache_file, "w"))
    
    def _get_modules(self, qemu):
        for each in self._get_optional_modules(qemu):
            self.optional_modules[each] = True
        for each in self._get_default_modules(qemu):
            self.default_modules[each] = True
        for each in self._get_blacklist_modules(qemu):
            self.blacklist_modules[each] = True
        return True
    
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

    def _get_unused_port(self):
        so = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        so.bind(('localhost', 0))
        _, port = so.getsockname()
        so.close()
        return port

    @property
    def repro(self):
        return self._repro
    
    @repro.setter
    def repro(self, value):
        if not isinstance(value, Reproducer):
            raise TypeError("repro must be an instance of Reproducer")
        self._init = True
        self._repro = value
    
    @property
    def root_user(self):
        return self._root_user
    
    @root_user.setter
    def root_user(self, user):
        self._root_user = user

    @property
    def normal_user(self):
        return self._normal_user
    
    @normal_user.setter
    def normal_user(self, user):
        self._normal_user = user

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
        if value == "android":
            self._type = 2
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
    def distro_src(self):
        return self._vendor_src
    
    @distro_src.setter
    def distro_src(self, value):
        if not os.path.exists(value):
            raise TargetFileNotExist(value)
        self._vendor_src = value
    
    @property
    def ssh_port(self):
        if self._ssh_port == None:
            return self._get_unused_port()
        return self._ssh_port
    
    @ssh_port.setter
    def ssh_port(self, n):
        if type(n) != int:
            raise TargetFormatNotMatch(n, type(n), int)
        self._ssh_port = n

    @property
    def gdb_port(self):
        if self._gdb_port == None:
            return self._get_unused_port()
        return self._gdb_port
    
    @gdb_port.setter
    def gdb_port(self, n):
        if type(n) != int:
            raise TargetFormatNotMatch(n, type(n), int)
        self._gdb_port = n

    @property
    def mon_port(self):
        if self._mon_port == None:
            return self._get_unused_port()
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
        if not regx_match(r'^\d+\.\d+\.\d+$', n):
            raise TargetFormatNotMatch(n, "x.x.x", n)
        self._distro_version = n

    @property
    def effective_cycle_start(self):
        return self._effective_cycle_start

    @effective_cycle_start.setter
    def effective_cycle_start(self, time_str):
        self._effective_cycle_start = time_str
    
    @property
    def effective_cycle_end(self):
        return self._effective_cycle_end

    @effective_cycle_end.setter
    def effective_cycle_end(self, time_str):
        self._effective_cycle_end = time_str
    
    @property
    def include(self):
        return self._include
    
    @include.setter
    def include(self, val):
        if type(val) != list:
            raise TargetFormatNotMatch(val, type(val), list)
        self._include = val
    
    @property
    def exclude(self):
        return self._exclude
    
    @exclude.setter
    def exclude(self, val):
        if type(val) != list:
            raise TargetFormatNotMatch(val, type(val), list)
        self._exclude = val