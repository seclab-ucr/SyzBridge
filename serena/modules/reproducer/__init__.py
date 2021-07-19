from .launcher import Launcher

class Reproducer(Launcher):
    def __init__(self, case_path, ssh_port, case_logger, debug, qemu_num):
        super().__init__(case_path, ssh_port, case_logger, debug=debug, qemu_num=qemu_num)