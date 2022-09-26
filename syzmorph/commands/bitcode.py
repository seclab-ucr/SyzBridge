import os, queue
import multiprocessing

from commands import Command
from syzmorph.infra.tool_box import *
from subprocess import Popen, STDOUT, PIPE, TimeoutExpired

class BitcodeCommand(Command):
    def __init__(self):
        super().__init__()
        self.args = None
        self.source_path = None
        self.config_path = None
        self.llvm_build_path = None
        self.bc_ready = False

        self.cmd_queue = multiprocessing.Queue()

    def add_arguments(self, parser):
        super().add_arguments(parser)
        parser.add_argument('--source', action='store', nargs='?', help='Kernel source path')
        parser.add_argument('--config', action='store', nargs='?', help='Config file for kernel compilation')
        parser.add_argument('--llvm', action='store', nargs='?', help='llvm binary path')

    def custom_subparser(self, parser, cmd):
        return parser.add_parser(cmd, help='Build kernel bitcode for static analysis')

    def run(self, args):
        self.args = args
        if self.have_clang_log() != 0:
            print("Cannot get clang log")
            return
        self.adjust_kernel_for_clang()
        self.compile_bc_extra()
    
    def adjust_kernel_for_clang(self):
        opts = ["-fno-inline-functions", "-fno-builtin-bcmp"]
        self._fix_asm_volatile_goto()
        self._add_extra_options(opts)
    
    def have_clang_log(self):
        self.source_path = self.args.source
        self.config_path = self.args.config
        self.llvm_build_path = self.args.llvm
        exitcode = 0

        if not os.path.exists(os.path.join(self.source_path, 'clang_log')):
            proj_path = os.path.join(os.getcwd(), "syzmorph")
            script_path = os.path.join(proj_path, "scripts/deploy-bc.sh")
            st = os.stat(script_path)
            os.chmod(script_path, st.st_mode | stat.S_IEXEC)
            p = Popen([script_path, self.source_path, self.config_path, self.llvm_build_path], cwd=self.source_path, stderr=STDOUT, stdout=PIPE)
            with p.stdout:
                self._log_subprocess_output(p.stdout)
            exitcode = p.wait()
        return exitcode
    
    def compile_bc_extra(self):
        regx = r'echo \'[ \t]*CC[ \t]*(([A-Za-z0-9_\-.]+\/)+([A-Za-z0-9_.\-]+))\';'
        base = self.source_path
        path = os.path.join(base, 'clang_log')

        procs = []
        for _ in range(0, 16):
            x = multiprocessing.Process(target=self.executor, args={base,})
            x.start()
            procs.append(x)
        with open(path, 'r') as f:
            lines = f.readlines()
            for line in lines:
                p2obj = regx_get(regx, line, 0)
                obj = regx_get(regx, line, 2)
                if p2obj == None or obj == None:
                    """cmds = line.split(';')
                    for e in cmds:
                        call(e, cwd=base)"""
                    continue
                if 'arch/x86/boot' in p2obj \
                    or 'arch/x86/entry/vdso' in p2obj \
                    or 'arch/x86/realmode' in p2obj:
                    continue
                #print("CC {}".format(p2obj))
                new_cmd = []
                try:
                    clang_path = '{}/bin/clang'.format(self.llvm_build_path)
                    idx1 = line.index(clang_path)
                    idx2 = line[idx1:].index(';')
                    cmd = line[idx1:idx1+idx2].split(' ')
                    if cmd[0] == clang_path:
                        new_cmd.append(cmd[0])
                        new_cmd.append('-emit-llvm')
                    #if cmd[0] == 'wllvm':
                    #    new_cmd.append('{}/tools/llvm/build/bin/clang'.format(self.proj_path))
                    #    new_cmd.append('-emit-llvm')
                    new_cmd.extend(cmd[1:])
                except ValueError:
                    print('No \'wllvm\' or \';\' found in \'{}\''.format(line))
                    raise ValueError
                idx_obj = len(new_cmd)-2
                st = new_cmd[idx_obj]
                if st[len(st)-1] == 'o':
                    new_cmd[idx_obj] = st[:len(st)-1] + 'bc'
                else:
                    print("{} is not end with .o".format(new_cmd[idx_obj]))
                    continue
                self.cmd_queue.put(new_cmd)
                """p = Popen(new_cmd, cwd=base, stdout=PIPE, stderr=PIPE)
                try:
                    p.wait(timeout=5)
                except TimeoutExpired:
                    if p.poll() == None:
                        p.kill()
                """

            self.bc_ready=True
            for p in procs:
                p.join()
            if os.path.exists(os.path.join(self.source_path,'one.bc')):
                os.remove(os.path.join(self.source_path,'one.bc'))
            link_cmd = '{}/bin/llvm-link -o one.bc `find ./ -name "*.bc" ! -name "timeconst.bc" ! -name "*.mod.bc"`'.format(self.llvm_build_path)
            p = Popen(['/bin/bash','-c', link_cmd], stdout=PIPE, stderr=STDOUT, cwd=base)
            with p.stdout:
                self._log_subprocess_output(p.stdout)
            exitcode = p.wait()
            if exitcode != 0:
                print("Fail to construct a monolithic bc")
            return exitcode
    
    def executor(self, base):
        while not self.bc_ready or not self.cmd_queue.empty():
            try:
                cmd = self.cmd_queue.get(block=True, timeout=5)
                obj = cmd[len(cmd)-2]
                print("CC {}".format(obj))
                p = Popen(" ".join(cmd), shell=True, cwd=base, stdout=PIPE, stderr=PIPE)
                #call(" ".join(cmd), shell=True, cwd=base)
                try:
                    p.wait(timeout=5)
                except TimeoutExpired:
                    if p.poll() == None:
                        p.kill()
                if p.poll() == None:
                    p.kill()
            except queue.Empty:
                # get() is multithreads safe
                # 
                break
    
    def _fix_asm_volatile_goto(self):
        regx = r'#define asm_volatile_goto'
        linux_repo = self.source_path
        compiler_gcc = os.path.join(linux_repo, "include/linux/compiler-gcc.h")
        buf = ''
        if os.path.exists(compiler_gcc):
            with open(compiler_gcc, 'r') as f_gcc:
                lines = f_gcc.readlines()
                for line in lines:
                    if regx_match(regx, line):
                        buf = line
                        break
            if buf != '':
                compiler_clang = os.path.join(linux_repo, "include/linux/compiler-clang.h")
                with open(compiler_clang, 'r+') as f_clang:
                    lines = f_clang.readlines()
                    data = [buf]
                    data.extend(lines)
                    f_clang.seek(0)
                    f_clang.writelines(data)
                    f_clang.truncate()
        return

    def _add_extra_options(self, opts):
        regx = r'KBUILD_CFLAGS[ \t]+:='
        linux_repo = self.source_path
        makefile = os.path.join(linux_repo, "Makefile")
        data = []
        with open(makefile, 'r+') as f:
            lines = f.readlines()
            for i in range(0, len(lines)):
                line = lines[i]
                if regx_match(regx, line):
                    parts = line.split(':=')
                    opts_str = " ".join(opts)
                    data.extend(lines[:i])
                    data.append(parts[0] + ":= " + opts_str + " " + parts[1])
                    data.extend(lines[i+1:])
                    f.seek(0)
                    f.writelines(data)
                    f.truncate()
                    break
    
    def _log_subprocess_output(self, pipe):
        try:
            for line in iter(pipe.readline, b''):
                try:
                    line = line.decode("utf-8").strip('\n').strip('\r')
                except:
                    print('bytes array \'{}\' cannot be converted to utf-8'.format(line))
                    continue
                print(line)
        except ValueError:
            if pipe.close:
                return