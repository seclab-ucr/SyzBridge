import json
import os

class Syscall:
    def __init__(self, path_package):
        json_path = os.path.join(path_package, "plugins/trace_validation/sym_exec/syscalls.json")
        self.syscall_table = json.load(open(json_path, 'r'))
    
    def number_of_arguments(self, syscall):
        if syscall not in self.syscall_table:
            return -1
        info = self.syscall_table[syscall]
        return len(info['args'].keys())
    
    def regs_of_syscall(self, syscall):
        if syscall not in self.syscall_table:
            return []
        info = self.syscall_table[syscall]
        return info['args'].keys()
    
    def synthesize_syscall(self, syscall, dst):
        snippet="""#define _GNU_SOURCE
  
#include <sys/syscall.h>
#include <unistd.h>

int main(void)
{
        syscall({{}}, {{}});
}
"""
        if syscall not in self.syscall_table:
            return False
        nr = '__NR_' + syscall
        args = []
        for _ in range(0, self.number_of_arguments(syscall)):
            args.append(0)
        
        snippet.format(nr, ", ".join(args))

        with open(dst, "w") as f:
            f.writelines(snippet)
        return True

