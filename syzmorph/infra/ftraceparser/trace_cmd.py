from subprocess import Popen, PIPE, STDOUT, call
from ftraceparser.tool_box import *

class TraceCmd():
    def __init__(self, prog, plugin="function_graph"):
        self.prog = prog
        self.plugin = plugin
    
    def get_record_cmd(self):
        """
        Builds the trace-cmd record command
        """
        syscalls = self.extract_syscalls()
        if syscalls is None:
            return None
        cmd = self.build_trace_cmd_command("record", syscalls)
        return cmd

    def build_trace_cmd_command(self, subcmd, entries):
        if subcmd == "record":
            cmd = "trace-cmd record "
            cmd += "-p {} ".format(self.plugin)
            cmd += "-g " + " -g ".join(entries) + " "
            cmd += "./poc"
            return cmd
    
    def extract_syscalls(self):
        """
        Extracts the syscall names from the trace-cmd output
        """
        readelf_regx = r'(\d+):( )+[0-9a-f]+( )+\d+( )+(\w+)( )+(\w+)( )+(\w+)( )+(\w+)( )+([a-zA-Z0-9\._-]+)?'
        common_setup_syscalls = ['mmap', 'waitpid', 'kill', 'signal', 'exit', 'unshare', 'setrlimit', 'chdir', 'chmod', 'prctl',\
            'poll', 'getrlimit', 'setrlimit', 'prlimit', 'sysinfo', 'munmap', 'mremap', 'getcwd', 'mprotect']
        syscalls = []
        enabled_syscalls = ['process_one_work', 'do_kern_addr_fault', 'handle_irq_event']

        try:
            p = Popen("trace-cmd list -f | grep -E \"^__x64_sys_\"",
                shell=True,
                stderr=STDOUT,
                stdout=PIPE)
        except Exception as e:
            print(e)
            return None
        output = []
        with p.stdout:
            for line in iter(p.stdout.readline, b''):
                line = line.decode("utf-8")
                output.append(line)
                if line.startswith("__x64_sys_"):
                    syscalls.append(line.strip())
        
        if syscalls == []:
            print("No syscalls found in trace-cmd output. Might need to run as root.")
            print("".join(output))
            return None

        p = Popen(["readelf", "-s", "{}".format(self.prog)],
            stderr=STDOUT,
            stdout=PIPE)
        with p.stdout:
            for line in iter(p.stdout.readline, b''):
                line = line.decode("utf-8")
                if regx_match(readelf_regx, line):
                    m = regx_getall(readelf_regx, line)[0]
                    type = m[4]
                    if type == 'FUNC':
                        name = m[12]
                        if name in common_setup_syscalls:
                            continue
                        name = '__x64_sys_' + name
                        if name in enabled_syscalls:
                            continue
                        if name in syscalls:
                            if name == '__x64_sys_recv':
                                enabled_syscalls.extend['__x64_sys_recv', '__x64_sys_recvfrom']
                            elif name == '__x64_sys_send':
                                enabled_syscalls.extend['__x64_sys_send', '__x64_sys_sendto']
                            else:
                                enabled_syscalls.append(name)
        return enabled_syscalls