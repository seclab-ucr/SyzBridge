from .instance import VMInstance
from .state import VMState

class VM(VMInstance, VMState):
    def __init__(self, linux, kernel, port, image, hash_tag, key, vmlinux=None, tag='', arch='amd64', work_path='/tmp/', mem="8G", cpu="4", gdb_port=-1, mon_port=-1, timeout=None, debug=False, logger=None, log_name='vm.log', log_suffix="", snapshot=True):
        self.only_instance = True
        VMInstance.__init__(self, tag=tag, work_path=work_path, log_name=log_name, log_suffix=log_suffix, logger=logger, hash_tag=hash_tag, debug=debug)
        self.setup(linux=linux, kernel=kernel, port=port, image=image, mem=mem, cpu=cpu, key=key, gdb_port=gdb_port, mon_port=mon_port, timeout=timeout, snapshot=snapshot)
        if vmlinux != None:
            self.only_instance = False
            VMState.__init__(self, vmlinux, gdb_port, arch, work_path=work_path, log_suffix=log_suffix, debug=debug)
    
    def destroy(self):
        self.logger.info("Destory QEMU on demand")
        if not self.only_instance:
            if self.gdb != None:
                self.gdb.close()
            if self.mon != None:
                self.mon.close()
            if self.gdb_kernel != None and self.gdb_kernel.proj != None:
                del self.gdb_kernel.proj
        self.kill_vm()