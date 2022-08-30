from .instance import VMInstance
from .state import VMState

class VM(VMInstance, VMState):
    def __init__(self, linux, cfg, port, image, hash_tag, key, vmlinux=None, tag='', arch='amd64', work_path='/tmp/', mem="8G", cpu="8", gdb_port=None, mon_port=None, timeout=None, debug=False, logger=None, log_name='vm.log', log_suffix="", snapshot=True):
        VMInstance.__init__(self, tag=tag, work_path=work_path, log_name=log_name, log_suffix=log_suffix, logger=logger, hash_tag=hash_tag, debug=debug)
        self.setup(linux=linux, cfg=cfg, port=port, image=image, mem=mem, cpu=cpu, key=key, gdb_port=gdb_port, mon_port=mon_port, timeout=timeout, snapshot=snapshot)
        if vmlinux != None:
            VMState.__init__(self, vmlinux, gdb_port, arch, work_path=work_path, log_suffix=log_suffix, debug=debug)
    
    def kill(self):
        self.logger.info("Kill QEMU on demand")
        self.kill_vm()
        if self.gdb != None:
            self.gdb.close()
        if self.mon != None:
            self.mon.close()
        if self.kernel != None and self.kernel.proj != None:
            del self.kernel.proj
        if self._output_lock.locked():
            self._output_lock.release()
        if self.lock.locked():
            self.lock.release()