import logging

from .tool_box import request_get, regx_get
from .strings import syscall_data_path


class SyzRepro():
    def __init__(self, url=None, text=None):
        self.syz_call = []
        self.call = []
        self.syscall_table = {}
        self.text = text
        if url != None:
            req = request_get(url)
            self.text = req.text
        self.build_syscall_table()
        self.build_repro()
    
    def build_syscall_table(self):
        with open(syscall_data_path, 'r') as f:
            data = f.readlines()
            for line in data:
                try:
                    pair = line.split(':')
                except Exception as e:
                    logging.error("{} is not a valid syscall pair")
                    continue
                self.syscall_table[pair[0]] = pair[1].strip()
    
    def build_repro(self):
        syscall_regx = r'^([A-Za-z0-9_.]+)(\$\w+)?'

        self.repro = []
        for line in self.text.split('\n'):
            if line.startswith('#'):
                continue
            i = line.index('=')
            reg = line[:i]
            syscall = line[i+1:]
            syscall_name = regx_get(syscall_regx, syscall, 0)
            self.syz_call.append(syscall_name)
            if syscall_name not in self.syscall_table:
                logging.error("{} is not a valid syscall name".format(syscall_name))
                continue
            self.call.append(self.syscall_table[syscall_name])