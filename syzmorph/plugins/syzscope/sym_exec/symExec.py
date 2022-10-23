import logging
from .stateManager import StateManager
import time
import angr
import math
import threading
import archinfo
import infra.tool_box as utilities
import datetime
import sys

from modules.vm import VM, VMInstance
from math import e
from modules.vm.error import QemuIsDead
from .mem_instrument import MemInstrument
from .error import VulnerabilityNotTrigger, ExecutionError, AbnormalGDBBehavior, InvalidCPU

class SymExec(MemInstrument):
    def __init__(self, index, workdir, syzscope, sections=None, logger=None, debug=False):
        MemInstrument.__init__(self, index, workdir, logger)
        self.syzscope = syzscope
        self.debug = debug
        self.vul_mem_offset = None
        self.vul_mem_size = None
        self.vul_mem_start = None
        self.vul_mem_end = None
        self.extra_noisy_func = None
        self.gdb_port = None
        self.mon_port = None
        self.vm = None
        self.proj = None
        self.simgr = None
        self._init_state = None
        self._timeout=None
        self._context_ready = False
        self._fallen_state = False
        self._out_of_time = False
        self.cus_sections = sections
        self.impacts_collector = {}
        self._branches = None
        self.target_site = None
        self.terminating_func = None
        self.start_time = None
        self.rel_type = -1
        self.state_tracking = []
        self.out_loop_states = []
        if logger == None:
            self.logger = logging
        else:
            self.logger = logger
    
    def init_execution(self):
        self.init_StateManager()
        self._branches = {}
        self.target_site = {}

    def setup_vm(self, distro, timeout, ssh_port=None, gdb_port=None, mon_port=None, log_name="vm.log", log_suffix="", **kwargs):
        self.proj_path = self.syzscope.path_case_plugin
        if timeout != None:
            self._timeout = timeout
        self.vm = distro.repro.launch_qemu(c_hash = self.syzscope.case_hash, log_name=log_name, log_suffix=log_suffix, \
            timeout=timeout, ssh_port=ssh_port, gdb_port=gdb_port, mon_port=mon_port, **kwargs)
        self.ssh_port = distro.repro.ssh_port
        self.gdb_port = distro.repro.gdb_port
        self.mon_port = distro.repro.mon_port
        return self.vm
    
    def cleanup(self):
        super().cleanup()
        if self.vm != None:
            self.vm.destroy()

    def setup_bug_capture(self, extra_noisy_func=None):
        self.extra_noisy_func = extra_noisy_func

    def prepare_angr(self):
        self.logger.info("Loading kernel into angr")
        self.vm.gdb_attach_vmlinux()
        self.vm.load_angr_proj()

    def setup_gdb_and_monitor(self, qemu: VMInstance):
        if self.vm == None:
            self.logger.error("Call setup_vm() to initialize the vm first")
            return True
        
        kaslr = True
        out = qemu.command(cmds="dmesg | grep nokaslr", timeout=5, wait=True, user='root')
        for line in out:
            if "nokaslr" in line:
                kaslr = False
                break
        if kaslr:
            self.logger.error("KASLR enabled, cannot proceed symbolic execution")
            return False

        self.vm.timeout = 5*60
        if not self.vm.gdb_connect(self.gdb_port):
            self.logger.error("SyzScope does not support current gdb, please change to pwndbg in ~/.gdbinit")
            qemu.destroy()
            return False
        if not self.vm.set_checkpoint():
            self.logger.error("No kasan_report() found")
            qemu.destroy()
            return False
        self.proj = self.vm.kernel.proj
        self.vm.mon_connect(self.mon_port)
        return True

    def run_sym(self, path=[], terminating_func='', raw_tracing=False, timeout=60*10):
        dfs = True
        if path == [] and not self.debug:
            dfs = False
        self._timeout = timeout
        if not self._context_ready:
            if self.vm == None:
                self.logger.error("Call setup_vm() to initialize the vm first")
                raise VulnerabilityNotTrigger
            self.vm.lock_thread()
            vul_mem = self._read_vul_mem()
            if vul_mem == None:
                self.logger.error("vulnerable oject addr is incorrect: {}".format(vul_mem))
                raise VulnerabilityNotTrigger   
            self.vm.back_to_kasan_ret()
            self._after_gdb_resume(300)
            self._find_vul_mem_bound(vul_mem)
            self.logger.info("Vuln mem: {} to {}".format(hex(self.vul_mem_start), hex(self.vul_mem_end)))
            self._context_ready = True
            self.vm.timeout = self._timeout+5*60
        return self.symbolic_execute(path, terminating_func, dfs=dfs, raw_tracing=raw_tracing)
    
    def symbolic_execute(self, path, terminating_func, dfs=True, raw_tracing=False):
        extras = {#angr.options.CONSERVATIVE_READ_STRATEGY,
                  #angr.options.CONSERVATIVE_WRITE_STRATEGY,
                  #angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                  angr.options.KEEP_IP_SYMBOLIC,
                  angr.options.CONSTRAINT_TRACKING_IN_SOLVER,
                  angr.options.REGION_MAPPING,
                  angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS}
        self._init_state = self.proj.factory.blank_state(addr=0, add_options=extras)
        self.setup_current_state(self._init_state)
        self._prepare_context()
        self._restore_memory()
        self._restore_registers()
        self._symbolize_vuln_mem(raw_tracing)
        if 'sym' not in self._init_state.globals or len(self._init_state.globals['sym']) == 0:
            return None
        ret = self.explore(terminating_func, path, raw_tracing, dfs)
        return ret

    def explore(self, terminating_func, path, raw_tracing, dfs):
        self.logger.info("Initial state explore at {}".format(hex(self._init_state.addr)))
        self.hook_noisy_func(self.extra_noisy_func)

        self._init_state.inspect.b('mem_read', when=angr.BP_BEFORE, action=self.track_mem_read)
        self._init_state.inspect.b('mem_write', when=angr.BP_BEFORE, action=self.track_mem_write)
        self._init_state.inspect.b('symbolic_variable', when=angr.BP_BOTH, action=self.track_symbolic_variable)
        self._init_state.inspect.b('call', when=angr.BP_BEFORE, action=self.track_call)
        #self._init_state.inspect.b('instruction', when=angr.BP_BEFORE, action=self.track_instruction, instruction=0xffffffff81005672)

        self.terminating_func = terminating_func
        self.start_time = time.time()
        self._run_simgr(dfs, path, raw_tracing)
        
        self.logger.info("*******************primitives*******************\n")
        running_time = time.time() - self.start_time
        self.logger.info("Running for {}".format(str(datetime.timedelta(seconds=running_time))))
        if len(self.impacts_collector) == 0:
            self.logger.info("There is no primitive found")
            return self.state_privilege
        self.logger.info("Total {} primitives found during symbolic execution\n".format(len(self.impacts_collector)))
        n_OUW, n_AAW, n_AVW, n_FAW, n_FVW, n_CFH, n_IF= 0, 0, 0, 0, 0, 0, 0
        for addr in self.impacts_collector:
            each_primitive = self.impacts_collector[addr]
            if each_primitive == StateManager.OOB_UAF_WRITE:
                n_OUW += 1
            if each_primitive == StateManager.ARBITRARY_ADDR_WRITE:
                n_AAW += 1
            if each_primitive == StateManager.ARBITRARY_VALUE_WRITE:
                n_AVW += 1
            if each_primitive == StateManager.FINITE_ADDR_WRITE:
                n_FAW += 1
            if each_primitive == StateManager.FINITE_VALUE_WRITE:
                n_FVW += 1
            if each_primitive == StateManager.CONTROL_FLOW_HIJACK:
                n_CFH += 1
            if each_primitive == StateManager.INVALID_FREE:
                n_IF += 1
        self.logger.info("The number of OOB/UAF write is {}\n".format(n_OUW))
        self.logger.info("The number of arbitrary address write is {}\n".format(n_AAW))
        self.logger.info("The number of constrained address write is {}\n".format(n_FAW))
        self.logger.info("The number of arbitrary value write is {}\n".format(n_AVW))
        self.logger.info("The number of constrained value write is {}\n".format(n_FVW))
        self.logger.info("The number of control flow hijacking is {}\n".format(n_CFH))
        self.logger.info("The number of invalid free is {}\n".format(n_IF))
        self.logger.info("************************************************\n")

        return self.state_privilege
    
    def _run_simgr(self, dfs, path, raw_tracing):
        self.init_execution()
        #self.build_path_fence(path)
        self.build_path_table(path)
        self.setup_current_state(self._init_state.copy())
        ok, err = self.init_simgr(raw_tracing, dfs)
        if not ok:
            self.logger.error(err)
            return
        meta_time = 0
        last_state = 0
        self.reset_state_bb()

        self.logger.info("Time limit: {} seconds".format(self._timeout))
        while True:
            if self._timeout != None:
                current_time = time.time()
                if meta_time == 0:
                    meta_time = current_time + 60*60
                if current_time >= meta_time:
                    self.logger.info("{} seconds left".format(self._timeout - (meta_time - self.start_time)))
                    meta_time = current_time + 60*60
                #self.logger.info("time left: {}".format(current_time - start_time))
                if not self._out_of_time and current_time - self.start_time >= self._timeout / 2:
                    self.logger.info("We are out of time")
                    self._out_of_time = True
                if current_time - self.start_time > self._timeout:
                    self.logger.info("Timeout, stop symbolic execution")
                    self.stop_execution = True

            if self.dfs:
                cur_state = self.get_state_index(self.get_current_state())
                if last_state != cur_state:
                    #self.dump_stack(self.get_current_state())
                    self.logger.info("Switch state {} to state {}".format(last_state, cur_state))
                    last_state = cur_state

            try:
                self.simgr.step(successor_func=self._my_successor_func)
            #except Exception as e:
             #   self.logger.info("Unexpected error occur: {}".format(str(e)))
              #  raise ExecutionError
            except ExecutionError:
                self.stop_execution = True
            
            if self.debug and len(self.simgr.active) == 1:
                #self.logger.info("=======dump========")
                try:
                    insns = self.proj.factory.block(self.simgr.active[0].addr).capstone.insns
                    n = len(insns)
                    self.vm.inspect_code(self.simgr.active[0].addr, n)
                except:
                    pass
                #file, line = self.vm.get_dbg_info(self.simgr.active[0].scratch.ins_addr)
                #print(file, line)
            
            if self.simgr.unconstrained:
                killed_state = []
                for each in self.simgr.unconstrained:
                    if each.regs.rip.symbolic:
                        if each.scratch.ins_addr not in self.exploitable_state:
                            self.wrap_high_risk_state(each, StateManager.CONTROL_FLOW_HIJACK)
                        killed_state.append(each)
                    for each in killed_state:
                        if each in self.simgr.unconstrained:
                            self.simgr.unconstrained.remove(each)

            if len(self.simgr.active) == 0:
                # No dfs no deferred
                if dfs:
                    if len(self.simgr.deferred) == 0:
                        self.logger.info("No active states")
                        self.stop_execution = True
                else:
                    self.logger.info("No active states")
                    self.stop_execution = True
            
            if self.stop_execution:
                self.stop_execution = False
                self.impacts_collector = self.exploitable_state
                return
    
    def _collect_propogating_results(self):
        self.logger.info("Dump symbolic propagations")
        ret = self.ppg_handler.get_symbolic_propagation()
        for each in ret:
            if type(each) == dict:
                self.logger.info("index: {}  pc: {}  addr: {}".format(each['kasan_write_index'], hex(each['pc']), hex(each['write_to_mem'])))
                t = self.vm.inspect_code(each['pc'], 1)
                self.logger.info(t)
                self.logger.info("stack:")
                for s in each['stack']:
                    self.logger.info(s)
        return ret


    def _symbolize_vuln_mem(self, raw_tracing):
        for i in range(0, self.vul_mem_size, self.vm.addr_bytes):
            self.make_symbolic(self._init_state, self.vul_mem_start + i, self.vm.addr_bytes, "s_obj_{}".format(self.vul_mem_start + i))
            if raw_tracing:
                val = self.vm.read_mem(self.vul_mem_start + i, 1)
                if len(val) == 1:
                    bv = self._init_state.memory.load(self.vul_mem_start + i, size=self.vm.addr_bytes, inspect=False, endness=archinfo.Endness.LE)
                    if not bv.symbolic:
                        self.logger.info("Vulnerable memory ({}) is not symbolic".format(hex(self.vul_mem_start + i)))
                        continue
                    self._init_state.solver.add(bv == val[0])
                else:
                    self.logger.info("Vulnerable memory has strange data: {}".format(val))
                    return
    
    def _restore_registers(self):
        regs = self.vm.read_regs()
        if self.vm.addr_bytes == 8:
            self._init_state.regs.gs = self._init_state.solver.BVV(self.get_segment_base('gs'), 64)
            #self._init_state.regs.cs = self._init_state.solver.BVV(regs['cs'], 32)
            #self._init_state.regs.ss = self._init_state.solver.BVV(regs['ss'], 32)
            #self._init_state.regs.ds = self._init_state.solver.BVV(regs['ds'], 32)
            self._init_state.regs.fs = self._init_state.solver.BVV(self.get_segment_base('fs'), 64)
            #self._init_state.regs.es = self._init_state.solver.BVV(self.get_segment_base('fs'), 64)
            if 'eflags' in regs:
                self._init_state.regs.eflags = self._init_state.solver.BVV(regs['eflags'], 32)
            else:
                raise AbnormalGDBBehavior
            self._init_state.regs.cr0 = self._init_state.solver.BVV(self.vm.read_reg('cr0'), 32)
            self._init_state.regs.cr2 = self._init_state.solver.BVV(self.vm.read_reg('cr2'), 64)
            self._init_state.regs.cr3 = self._init_state.solver.BVV(self.vm.read_reg('cr3'), 64)
            self._init_state.regs.cr4 = self._init_state.solver.BVV(self.vm.read_reg('cr4'), 32)
            self._init_state.regs.cr8 = self._init_state.solver.BVV(self.vm.read_reg('cr8'), 64)
            if self.vm.addr_bytes == 8:
                self._init_state.regs.rax = self._init_state.solver.BVV(regs['rax'], 64)
                self._init_state.regs.rbx = self._init_state.solver.BVV(regs['rbx'], 64)
                self._init_state.regs.rcx = self._init_state.solver.BVV(regs['rcx'], 64)
                self._init_state.regs.rdx = self._init_state.solver.BVV(regs['rdx'], 64)
                self._init_state.regs.rsi = self._init_state.solver.BVV(regs['rsi'], 64)
                self._init_state.regs.rdi = self._init_state.solver.BVV(regs['rdi'], 64)
                self._init_state.regs.rsp = self._init_state.solver.BVV(regs['rsp'], 64)
                self._init_state.regs.rbp = self._init_state.solver.BVV(regs['rbp'], 64)
                self._init_state.regs.r8 = self._init_state.solver.BVV(regs['r8'], 64)
                self._init_state.regs.r9 = self._init_state.solver.BVV(regs['r9'], 64)
                self._init_state.regs.r10 = self._init_state.solver.BVV(regs['r10'], 64)
                self._init_state.regs.r11 = self._init_state.solver.BVV(regs['r11'], 64)
                self._init_state.regs.r12 = self._init_state.solver.BVV(regs['r12'], 64)
                self._init_state.regs.r13 = self._init_state.solver.BVV(regs['r13'], 64)
                self._init_state.regs.r14 = self._init_state.solver.BVV(regs['r14'], 64)
                self._init_state.regs.r15 = self._init_state.solver.BVV(regs['r15'], 64)
                self._init_state.regs.rip = self._init_state.solver.BVV(regs['rip'], 64)
                self._init_state.regs.xmm0 = self._init_state.solver.BVV(self.vm.read_reg('xmm00'), 128)
                self._init_state.regs.xmm1 = self._init_state.solver.BVV(self.vm.read_reg('xmm01'), 128)
                self._init_state.regs.xmm2 = self._init_state.solver.BVV(self.vm.read_reg('xmm02'), 128)
                self._init_state.regs.xmm3 = self._init_state.solver.BVV(self.vm.read_reg('xmm03'), 128)
                self._init_state.regs.xmm4 = self._init_state.solver.BVV(self.vm.read_reg('xmm04'), 128)
                self._init_state.regs.xmm5 = self._init_state.solver.BVV(self.vm.read_reg('xmm05'), 128)
                self._init_state.regs.xmm6 = self._init_state.solver.BVV(self.vm.read_reg('xmm06'), 128)
                self._init_state.regs.xmm7 = self._init_state.solver.BVV(self.vm.read_reg('xmm07'), 128)
                self._init_state.regs.xmm8 = self._init_state.solver.BVV(self.vm.read_reg('xmm08'), 128)
                self._init_state.regs.xmm9 = self._init_state.solver.BVV(self.vm.read_reg('xmm09'), 128)
                self._init_state.regs.xmm10 = self._init_state.solver.BVV(self.vm.read_reg('xmm10'), 128)
                self._init_state.regs.xmm11 = self._init_state.solver.BVV(self.vm.read_reg('xmm11'), 128)
                self._init_state.regs.xmm12 = self._init_state.solver.BVV(self.vm.read_reg('xmm12'), 128)
                self._init_state.regs.xmm13 = self._init_state.solver.BVV(self.vm.read_reg('xmm13'), 128)
                self._init_state.regs.xmm14 = self._init_state.solver.BVV(self.vm.read_reg('xmm14'), 128)
                self._init_state.regs.xmm15 = self._init_state.solver.BVV(self.vm.read_reg('xmm15'), 128)
            if self.vm.addr_bytes == 4:
                self._init_state.regs.eax = self._init_state.solver.BVV(regs['eax'], 64)
                self._init_state.regs.ebx = self._init_state.solver.BVV(regs['ebx'], 64)
                self._init_state.regs.ecx = self._init_state.solver.BVV(regs['ecx'], 64)
                self._init_state.regs.edx = self._init_state.solver.BVV(regs['edx'], 64)
                self._init_state.regs.esi = self._init_state.solver.BVV(regs['esi'], 64)
                self._init_state.regs.edi = self._init_state.solver.BVV(regs['edi'], 64)
                self._init_state.regs.esp = self._init_state.solver.BVV(regs['esp'], 64)
                self._init_state.regs.ebp = self._init_state.solver.BVV(regs['ebp'], 64)
                self._init_state.regs.eip = self._init_state.solver.BVV(regs['eip'], 64)

    def _prepare_context(self):
        pc = 0
        val = self.vm.gdb.get_register('rip')
        if val != None:
            pc = val
        if val == None and self.vm.addr_bytes == 4:
            val = self.vm.gdb.get_register('eip')
            if val != None:
                pc = val
        if pc == 0:
            return
        if not self.vm.prepare_context(pc):
            raise InvalidCPU

    def _restore_memory(self):
        self.setup_sections(self.cus_sections)
        self.setup_segment_base()
        #self.vm.read_stack_range()
    
    def skip_unexpected_opcode(self, addr):
        skip_opcode = ['rdtsc', 'in', 'out']
        error_opcode = ['ud0', 'ud1', 'ud2', 'int3']
        insns = self.proj.factory.block(addr).capstone.insns
        if len(insns) == 0:
            code = self.vm.inspect_code(addr, 1)
            if 'ud' in code or 'int3' in code:
                self.logger.info("Unexpected opcode")
                self.logger.debug(code)
                self.purge_current_state()
            if not self.proj.is_hooked(addr):
                self.skip_insn(addr, 1)
                return
        offset = 0
        for inst in insns:
            opcode = inst.mnemonic
            if opcode in error_opcode:
                self.logger.info("Unexpected opcode")
                self.logger.debug(opcode)
                self.purge_current_state()
            if opcode in skip_opcode or opcode in error_opcode:
                if not self.proj.is_hooked(addr+offset):
                    self.skip_insn(addr+offset, 2)
            offset += inst.size
        return

    def _is_vul_mem(self, addr):
        if addr >= self.vul_mem_start and addr <= self.vul_mem_end:
            return True
        return False
    
    def build_path_fence(self, paths):
        self._branches['correct'] = {}
        self._branches['wrong'] = {}
        for each_path in paths:
            for each_node in each_path:
                self._branches['correct'][each_node['correct']] = 0
                self._branches['wrong'][each_node['wrong']] = 0

    def build_path_table(self, paths):
        for each_path in paths:
            for i in range(0, len(each_path)-1):
                each_branch = each_path[i]
                cond = each_branch['cond']
                correct = each_branch['correct']
                wrong = each_branch['wrong']
                key = "{}:{}".format(cond['file'], cond['line'])
                if key not in self._branches:
                    self._branches[key] = []
                new_correct_bb = True
                new_wrong_bb = True
                for exist_br in self._branches[key]:
                    if exist_br['file'] == correct['file'] and exist_br['line'] == correct['line']:
                        new_correct_bb = False
                        if not exist_br['feasible']:
                            exist_br['feasible'] = True
                    if exist_br['file'] == wrong['file'] and exist_br['line'] == wrong['line']:
                        new_wrong_bb = False
                if new_correct_bb:
                    self._branches[key].append(correct)
                if new_wrong_bb and (wrong['file'] != correct['file'] or wrong['line'] != correct['line']):
                    self._branches[key].append(wrong)
            if len(each_path) > 0:
                key = "{}:{}".format(each_path[len(each_path)-1]['file'], each_path[len(each_path)-1]['line'])
                self.target_site[key] = StateManager.NO_ADDITIONAL_USE
                self.guided = True
    
    def add_to_debug_trace(self, state):
        file, line = self.vm.get_dbg_info(state.addr)
        for each in self.state_tracking:
            if file == each['file'] and line == each['line']:
                return
        self.state_tracking.append({'file': file, 'line': line})
    
    def maintain_debug_trace(self, state):
        for addr in state.history.bbl_addrs: 
            func_name = self.vm.get_func_name(addr)
            file, line = self.vm.get_dbg_info(addr)
            if func_name == None or file == None or line == None:
                continue
            if 'kasan' in file or 'kcov' in file:
                continue
            for each_state in self.state_tracking:
                if file == each_state['file'] and line == each_state['line']:
                    self.dump_stack(state)
                    self.dump_trace(state)
                

    def _match_fense(self, next_state):
        addr = next_state.addr
        insns = self.proj.factory.block(addr).capstone.insns
        for each_inst in insns:
            if addr in self._branches['wrong']:
                return True
            addr += each_inst.size
        return addr in self._branches['wrong']
    
    def _match_next_bb_on_path(self, state, successor):
        file, line = self.vm.get_dbg_info(state.addr)
        key = "{}:{}".format(file, line)
        self.logger.info("locate {}".format(key))
        other = {}
        other[successor[0]] = successor[1]
        other[successor[1]] = successor[0]
        for next_state in successor:
            next_file, next_line = self.vm.get_dbg_info(next_state.addr)
            if key in self._branches:
                for each_bb in self._branches[key]:
                    if each_bb['file'] == next_file and each_bb['line'] == next_line and each_bb['feasible']:
                        self.logger.info("A correct branch detected {}:{}".format(next_file, next_line))
                        return other[next_state]
                    if each_bb['file'] == next_file and each_bb['line'] == next_line and not each_bb['feasible']:
                        self.logger.info("A wrong branch detected {}:{}".format(next_file, next_line))
                        return next_state
            else:
                return None
            return None
        """if key in self._branches:
            for each_bb in self._branches[key]:
                if each_bb['file'] == next_file and each_bb['line'] == next_line \
                        and not each_bb['feasible'] \
                        and (next_file != file or next_line != line): # Sometimes the dbg info messed up, do not kill the state
                    return False
        return True
        """
    
    def _my_successor_func(self, state):
        self.setup_current_state(state)
        self.skip_unexpected_opcode(state.addr)
        try:
            succ = state.step()
        except Exception as e:
            self.logger.error("Execution error at {}".format(hex(state.scratch.ins_addr)))
            code = self.vm.inspect_code(state.scratch.ins_addr, 1)
            if code != None:
                self.logger.info(code)
            self.logger.error(e)
            self.kill_current_state = False
            succ = self.proj.factory.successors(state)
            self._fallen_state = True
            #raise ExecutionError
        if self._is_fallen_state(state):
            self.logger.warning("kill a fallen state")
            succ.flat_successors = []
            succ.all_successors = []
            self.kill_current_state = False
            return succ
        successors = succ.successors
        if len(succ.successors) == 1:
            insns = self.proj.factory.block(state.addr).capstone.insns
            n = len(insns)
            # Only logging top-level function ret
            if n >0 and insns[n-1].mnemonic == 'ret' and state.callstack.next == None and successors[0].callstack.next == None:
                func_name = self.vm.get_func_name(successors[0].addr)
                file, line = self.vm.get_dbg_info(successors[0].addr)
                self.update_states_globals(0, "{} {}:{}".format(func_name, file, line), StateManager.G_RET)

        self.transfer_state_globals(state, successors)
        if len(succ.successors) == 1:
            self.update_states(successors[0], self.get_state_index(state))
        if len(succ.successors) == 2:
            self.update_states(successors[0], self.get_state_index(state))
            self.update_states(successors[1], None)  # sym will go this way first
            self.logger.info("state {}({}) fork state {}({}) at {} ".format(self.get_state_index(state), hex(successors[0].addr), self.state_counter, hex(successors[1].addr), hex(state.addr)))
            #cap = self.proj.factory.block(each.addr).capstone
            #cap.pp()

        dead_states = []
        # kill states with non-kernel-space pc
        if state.addr < self.vm.KERNEL_BASE or self.kill_current_state:
            if self.kill_current_state:
                self.logger.warning("state {} has been purged".format(self.get_state_index(state)))
            self.kill_current_state = False
            dead_states.extend(successors)
        # kill states with multiple forking
        if len(successors) > 1:
            for i in range(0, len(successors)):
                successors[i].globals['bb'] = 0
            self._update_fork_countor(state)
            if self._is_loop_fork(state, successors):
                self.logger.info("kill a loop forking at {}".format(hex(state.addr)))
                dead_states.extend(successors)
                dead_states.extend(self.out_loop_states)
        # kill states on particular branches
        if len(self._branches) > 0 and self._is_branch(state.addr) and len(successors) == 2:
            wrong_state = self._match_next_bb_on_path(state, successors)
            if wrong_state != None:
                self.logger.info("kill a off path state: state {}".format(self.get_state_index(wrong_state)))
                dead_states.append(wrong_state)
        for each in dead_states:
            if each in succ.successors:
                succ.successors.remove(each)
            if each in succ.flat_successors:
                succ.flat_successors.remove(each)
            if each in succ.all_successors :
                succ.all_successors.remove(each)

        return succ

    def _is_loop_fork(self, state, successors):
        callstack = state.callstack
        stack = [state.addr]
        while True:
            if callstack.next == None:
                break
            call_site = callstack.call_site_addr
            callstack = callstack.next
            stack.append(call_site)
            if len(stack) > 2:
                break
        if len(stack) == 1:
            stack.extend([0,0])
        if len(stack) == 2:
            stack.append(0)
        if stack[0] not in self.fork_countor:
            return False
        if stack[1] not in self.fork_countor[stack[0]]:
            return False
        if stack[2] not in self.fork_countor[stack[0]][stack[1]]:
            return False
        if not self._out_of_time:
            self.out_loop_states.extend(successors)
            self._mark_out_loop_state(successors)
            if self.fork_countor[stack[0]][stack[1]][stack[2]] >= StateManager.MAX_FORK_LOOP*2:
                return True
            else:
                return False
        return self.fork_countor[stack[0]][stack[1]][stack[2]] >= StateManager.MAX_FORK_LOOP
    
    def _update_fork_countor(self, state):
        callstack = state.callstack
        stack = [state.addr]
        while True:
            if callstack.next == None:
                break
            call_site = callstack.call_site_addr
            callstack = callstack.next
            stack.append(call_site)
            if len(stack) > 2:
                break
        if len(stack) == 1:
            stack.extend([0,0])
        if len(stack) == 2:
            stack.append(0)
        if stack[0] not in self.fork_countor:
            self.fork_countor[stack[0]] = {}
        if stack[1] not in self.fork_countor[stack[0]]:
            self.fork_countor[stack[0]][stack[1]] = {}
        if stack[2] not in self.fork_countor[stack[0]][stack[1]]:
            self.fork_countor[stack[0]][stack[1]][stack[2]] = 0
        self.fork_countor[stack[0]][stack[1]][stack[2]] += 1
    
    def _is_branch(self, addr):
        #jump_inst = [je', 'jne', 'jg', 'jge', 'ja', 'jae', 'jl', 'jle', 'jb', 'jbe',\
        #    'jo', 'jno', 'jz', 'jnz', 'js', 'jns', 'jcxz', 'jecxz', 'jrcxz', 'jnae', 'jc',\
        #    'jnc', 'jnb', 'jna', 'jnbe', 'jnge', 'jng', 'jnle', 'jp', 'jpe', 'jnp', 'jpo']
        insns = self.proj.factory.block(addr).capstone.insns
        length = len(insns)
        if length == 0:
            return False
        last_inst = insns[length - 1]
        return last_inst.mnemonic[0] == 'j' and last_inst.mnemonic != 'jmp'
    
    def _is_fallen_state(self, state):
        if self._fallen_state:
            self._fallen_state = False
            return True
        if self.out_of_scope:
            self.update_states_globals(0, 0, StateManager.G_BB)
            n = self.get_states_globals(0, StateManager.G_BB)
            return n > StateManager.MAX_BB_WITHOUT_SYM
        else:
            callstack = state.callstack
            try:
                insns = self.proj.factory.block(state.scratch.ins_addr).capstone.insns
            except:
                return False
            n = len(insns)
            if n == 0:
                return False
            func_name = self.vm.get_func_name(state.scratch.ins_addr)
            if callstack.next == None and insns[n-1].mnemonic == 'ret' and func_name == self.terminating_func:
                self.out_of_scope = True
                self.logger.info("Reach termination function")
                return False
            return False
    
    def _mark_out_loop_state(self, successors):
        for each_state in successors:
            self.update_states_globals(0, True, StateManager.G_LOOP, state=each_state)
    
    def _after_gdb_resume(self, timeout):
        self.vm.gdb.waitfor("Continuing")
        self.vm.gdb.waitfor("pwndbg>", timeout=timeout)

    def _read_vul_mem(self):
        self._after_gdb_resume(10*60)
        self.vm.gdb.waitfor("pwndbg>")
        rdi_val = self.vm.gdb.get_register('rdi')
        return rdi_val
    
    def _find_vul_mem_bound(self, vul_mem):
        self.vul_mem_offset, self.vul_mem_size, self.rel_type = utilities.extract_vul_obj_offset_and_size(self.vm.output)
        if self.vul_mem_offset == None or self.vul_mem_size == None:
            self.logger.error("vulnerable oject offset or size is incorrect: {} {}".format(self.vul_mem_offset, self.vul_mem_size))
            raise VulnerabilityNotTrigger   
        if self.rel_type == 0:
            self.vul_mem_start = vul_mem - self.vul_mem_offset
            self.vul_mem_end = self.vul_mem_start + self.vul_mem_size
            shadow_mem = utilities.kasan_mem_to_shadow(self.vul_mem_end)
            page = 4096
            for i in range(0, page): 
                t = self.vm.read_mem(shadow_mem+i, 1)
                if len(t) == 1:
                    if t[0] == 0xfb or t[0] == 0xfc or t[0] == 0xfe or t[0] == 0xff:
                        self.vul_mem_end += 8
                    if t[0] >= 0 and t[0] <= 7:
                        break
        elif self.rel_type == 1:
            self.vul_mem_start = vul_mem - self.vul_mem_offset
            self.vul_mem_end = self.vul_mem_start
            shadow_mem = utilities.kasan_mem_to_shadow(vul_mem)
            page = 4096
            for i in range(0, page): 
                t = self.vm.read_mem(shadow_mem+i, 1)
                if len(t) == 1:
                    if t[0] == 0xfb or t[0] == 0xfc or t[0] == 0xfe or t[0] == 0xff:
                        self.vul_mem_end += 8
                    if t[0] >= 0 and t[0] <= 7:
                        break
        elif self.rel_type == 2:
            self.vul_mem_start = vul_mem + self.vul_mem_offset - self.vul_mem_size
            self.vul_mem_end = self.vul_mem_start + self.vul_mem_size
        return

