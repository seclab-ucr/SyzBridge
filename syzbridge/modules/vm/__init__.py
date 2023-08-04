import functools
import inspect
from .qemu.instance import VMInstance
from .qemu.state import VMState
from .aemu.instance import AEmuInstance

class VM():
    DISTROS = 0
    UPSTREAM = 1
    ANDROID = 2
    def __init__(self, linux, kernel, port, image, hash_tag, key, vmlinux=None, tag='', arch='amd64', work_path='/tmp/', mem="4G", cpu="2", gdb_port=-1, mon_port=-1, timeout=None, debug=False, logger=None, log_name='vm.log', log_suffix="", snapshot=True):
        self.only_instance = True
        self._vm_instance = None
        if kernel.type == self.ANDROID:
            self._vm_instance = AEmuInstance(tag=tag, work_path=work_path, log_name=log_name, log_suffix=log_suffix, logger=logger, hash_tag=hash_tag, debug=debug)
            self._vm_instance.setup(linux=linux, kernel=kernel, port=port, image=image, mem=mem, cpu=cpu, key=key, gdb_port=gdb_port, mon_port=mon_port, timeout=timeout, snapshot=snapshot)
        else:
            self._vm_instance = VMInstance(tag=tag, work_path=work_path, log_name=log_name, log_suffix=log_suffix, logger=logger, hash_tag=hash_tag, debug=debug)
            self._vm_instance.setup(linux=linux, kernel=kernel, port=port, image=image, mem=mem, cpu=cpu, key=key, gdb_port=gdb_port, mon_port=mon_port, timeout=timeout, snapshot=snapshot)
            if vmlinux != None:
                self.only_instance = False
                VMState.__init__(self, vmlinux, gdb_port, arch, work_path=work_path, log_suffix=log_suffix, debug=debug)
    
    def __getattr__(self, func_name):
        try:
            method = getattr(self._vm_instance, func_name)
            if inspect.ismethod(method):
                return functools.partial(self._func_wrap, method)
            else:
                return method
        except:
            raise AttributeError("VM object has no attribute '{}'".format(func_name))
    
    def _func_wrap(self, method, *args, **kwargs):
        return method(*args, **kwargs)
        
    def destroy(self):
        self.logger.info("Destory QEMU on demand")
        if not self.only_instance:
            if self.gdb != None:
                self.gdb.close()
            if self.mon != None:
                self.mon.close()
            if self.gdb_kernel != None and self.gdb_kernel.proj != None:
                del self.gdb_kernel.proj
                self.gdb_kernel.proj = None
        self.kill_vm()