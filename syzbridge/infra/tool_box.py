import os, re, stat, sys
import time
import requests
import logging
import random
import datetime, json
from subprocess import call, Popen, PIPE, STDOUT
from os import get_terminal_size
from platform import platform, system

from .strings import *

FILE_HANDLER = 0
STREAM_HANDLER = 1

KASAN_NONE=0
KASAN_OOB=1
KASAN_UAF=2

NONCRITICAL = 0
AbMemRead = 1
AbMemWrite = 2
InvFree = 4

def get_terminal_width() -> int:
    try:
        width, _ = get_terminal_size()
    except OSError:
        width = 80

    if system().lower() == "windows":
        width -= 1

    return width

def regx_match(regx, line):
    m = re.search(regx, line)
    if m != None and len(m.group()) != 0:
        return True
    return False

def regx_match_list(regx_list, line):
    for regx in regx_list:
        if regx_match(regx, line):
            return True
    return False

def regx_get(regx, line, index):
    m = re.search(regx, line)
    if m != None and len(m.groups()) > index:
        return m.groups()[index]
    return None

def regx_getall(regx, line):
    m = re.findall(regx, line, re.MULTILINE)
    return m

def regx_kasan_line(line):
    m = re.search(trace_regx, line)
    if m != None:
        return m.groups()
    return None

def parse_one_trace(line):
    m = re.findall(trace_regx, line)[0]
    if len(m) < 6:
        return None, None
    func = m[0]
    src_file = m[3]
    return func, src_file

def is_kasan_func(source_path):
    if source_path == None:
        return False
    if regx_match(r'dump_stack.c', source_path) or regx_match(r'mm\/kasan', source_path):
        return True
    return False

def is_trace(line):
    return regx_match(trace_regx, line)

def extract_debug_info(line):
    res = regx_kasan_line(line)
    if res == None:
        return res
    return res[2]

def extract_bug_description(report):
    res = []
    record_flag = 0
    for line in report:
        if regx_match(bug_desc_begin_regx, line):
            record_flag ^= 1
        if regx_match(bug_desc_end_regx, line):
            record_flag ^= 1
        if record_flag:
            res.append(line)
    return res

def extract_bug_type(report):
    for line in report:
        if regx_match(r'KASAN: use-after-free', line):
            return KASAN_UAF
        if regx_match(r'KASAN: \w+-out-of-bounds', line):
            return KASAN_OOB
    return KASAN_NONE

def extract_bug_mem_addr(report):
    addr = None
    for line in report:
        addr = regx_get(kasan_read_addr_regx, line , 1)
        if addr != None:
            return int(addr, 16)
        addr = regx_get(kasan_write_addr_regx, line , 1)
        if addr != None:
            return int(addr, 16)
    return None

def extract_vul_obj_offset_and_size(report):
    rel_type = -1
    offset = None
    size = None
    bug_desc = extract_bug_description(report)
    bug_type = extract_bug_type(report)
    bug_mem_addr = extract_bug_mem_addr(report)
    if bug_mem_addr == None:
        #print("Failed to locate the memory address that trigger UAF/OOB")
        return offset, size, rel_type
    if bug_type == KASAN_NONE:
        return offset, size, rel_type
    if bug_type == KASAN_UAF or bug_type == KASAN_OOB:
        for line in bug_desc:
            if offset == None:
                offset = regx_get(offset_desc_regx, line, 0)
                if offset != None:
                    offset = int(offset)
                    if regx_match(r'inside', line):
                        rel_type = 0
                    if regx_match(r'to the right', line):
                        rel_type = 1
                    if regx_match(r'to the left', line):
                        rel_type = 2
            if size == None:
                size = regx_get(size_desc_regx, line, 0)
                if size != None:
                    size = int(size)
            if offset != None and size != None:
                break
        if offset == None:
            if len(bug_desc) == 0:
                return offset, size, rel_type
            line = bug_desc[0]
            addr_begin = regx_get(r'The buggy address belongs to the object at \w+', line, 0)
            if addr_begin != None:
                addr_begin = int(addr_begin, 16)
                offset = bug_mem_addr - addr_begin
        if size == None:
            size = offset
    return offset, size, rel_type

def extract_alloc_trace(report):
        res = []
        record_flag = 0
        call_trace_end = [r"entry_SYSENTER", r"entry_SYSCALL", r"ret_from_fork", r"bpf_prog_[a-z0-9]{16}\+", r"Freed by"]
        for line in report:
            if record_flag and is_trace(line):
                res.append(line)
                if is_kasan_func(extract_debug_info(line)):
                    res = []
            if regx_match(r'Allocated by task \d+', line):
                record_flag ^= 1
            if record_flag == 1 and regx_match_list(call_trace_end, line):
                record_flag ^= 1
                break
        return res[:-2]

def extract_free_trace(report):
        res = []
        record_flag = 0
        call_trace_end = [r"entry_SYSENTER", r"entry_SYSCALL", r"ret_from_fork", r"bpf_prog_[a-z0-9]{16}\+", r"The buggy address belongs", r"Memory state around"]
        for line in report:
            if record_flag and is_trace(line):
                res.append(line)
                if is_kasan_func(extract_debug_info(line)):
                    res = []
            if regx_match(r'Freed by task \d+', line):
                record_flag ^= 1
            if record_flag == 1 and regx_match_list(call_trace_end, line):
                record_flag ^= 1
                break
        return res[:-2]

def extrace_call_trace(report, start_with='Call Trace'):
    regs_regx = r'[A-Z0-9]+:( )+[a-z0-9]+'
    implicit_call_regx = r'\[.+\]  \?.*'
    fs_regx = r'FS-Cache:'
    ignore_func_regx = r'__(read|write)_once'
    call_trace_end = [r"entry_SYSENTER", r"entry_SYSCALL", r"ret_from_fork", r"bpf_prog_[a-z0-9]{16}\+", r"Allocated by"]
    exceptions = [" <IRQ>", " </IRQ>"]
    res = []
    record_flag = 0
    for line in report:
        line = line.strip('\n')
        if regx_match(start_with, line):
            record_flag = 1
            res = []
        if record_flag and is_trace(line):
            """not regx_match(implicit_call_regx, line) and \
            not regx_match(regs_regx, line) and \
            not regx_match(fs_regx, line) and \
            not regx_match(ignore_func_regx, line) and \
            not line in exceptions:"""
            res.append(line)
            """
            I cannot believe we do have a calltrace starting without dump_stack like this:

            __read_once_size include/linux/compiler.h:199 [inline]
            arch_atomic_read arch/x86/include/asm/atomic.h:31 [inline]
            atomic_read include/asm-generic/atomic-instrumented.h:27 [inline]
            dump_stack+0x152/0x1ca lib/dump_stack.c:114
            print_address_description.constprop.0.cold+0xd4/0x30b mm/kasan/report.c:375
            __kasan_report.cold+0x1b/0x41 mm/kasan/report.c:507
            kasan_report+0xc/0x10 mm/kasan/common.c:641
            """
            if is_kasan_func(extract_debug_info(line)):
                res = []
        if record_flag == 1 and regx_match_list(call_trace_end, line) and '?' not in line:
            record_flag ^= 1
            break
    return res

def chmodX(path):
    st = os.stat(path)
    os.chmod(path, st.st_mode | stat.S_IEXEC)

def request_get(url):
    '''
    Try request a url for 5 times with Chrome's User-Agent
    '''
    headers={'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36'}
    failed=0
    while failed<5:
        r=requests.request(method='GET', url=url,headers=headers)
        if r.status_code==200:
            print(f'[+]Success on crawl {url}')
            return r
        failed+=1
        print(f'[*]Failed on crawl {url} for {failed} times')
        time.sleep(5)
    #Ok... let's just return
    return requests.request(method='GET', url=url,headers=headers)

def init_logger(logger_id, cus_format='%(asctime)s %(message)s', debug=False, propagate=False, handler_type = FILE_HANDLER):
    ran = random.getrandbits(8)
    if (handler_type == FILE_HANDLER):
        handler = logging.FileHandler(logger_id)
        format = logging.Formatter(cus_format)
        handler.setFormatter(format)
    if (handler_type == STREAM_HANDLER):
        handler = logging.StreamHandler(sys.stdout)
        format = logging.Formatter(cus_format)
        handler.setFormatter(format)
    logger = logging.getLogger(logger_id)
    for each_handler in logger.handlers:
        logger.removeHandler(each_handler)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = propagate
    if debug:
        logger.setLevel(logging.DEBUG)
    return logger

def log_anything(pipe, logger, debug):
    try:
        for line in iter(pipe.readline, b''):
            try:
                line = line.decode("utf-8").strip('\n').strip('\r')
            except:
                logger.info('bytes array \'{}\' cannot be converted to utf-8'.format(line))
                continue
            logger.info(line)
            if debug:
                print(line)
    except ValueError:
        if pipe.close:
            return

def set_compiler_version(time, config_url):
    GCC = 0
    CLANG = 1
    regx_gcc_version = r'gcc \(GCC\) (\d+).\d+.\d+ (\d+)'
    regx_clang_version = r'clang version (\d+).\d+.\d+ \(https:\/\/github\.com\/llvm\/llvm-project\/ (\w+)\)'
    compiler = -1
    ret = ""
    
    r = request_get(config_url)
    text = r.text.split('\n')
    for line in text:
        if line.find('Compiler:') != -1:
            if regx_match(regx_gcc_version, line):
                compiler = GCC
                version = regx_get(regx_gcc_version, line, 0)
                commit = regx_get(regx_gcc_version, line, 1)
            if regx_match(regx_clang_version, line):
                compiler = CLANG
                version = regx_get(regx_clang_version, line, 0)
                commit = regx_get(regx_clang_version, line, 1)
            break
        if line.find('CONFIG_CC_VERSION_TEXT') != -1:
            if regx_match(regx_gcc_version, line):
                compiler = GCC
                version = regx_get(regx_gcc_version, line, 0)
                commit = regx_get(regx_gcc_version, line, 1)
            if regx_match(regx_clang_version, line):
                compiler = CLANG
                version = regx_get(regx_clang_version, line, 0)
                commit = regx_get(regx_clang_version, line, 1)
            break
    
    if compiler == GCC:
        if version == '7':
            ret = "gcc-7"
        if version == '8':
            ret = "gcc-8.0.1-20180412"
        if version == '9':
            ret = "gcc-9.0.0-20181231"
        if version == '10':
            ret = "gcc-10.1.0-20200507"

    if compiler == CLANG:
        if version == '7' and version.find('329060'):
            ret = "clang-7-329060"
        if version == '7' and version.find('334104'):
            ret = "clang-7-334104"
        if version == '8':
            ret = "clang-8-343298"
        if version == '10':
            #clang-10-c2443155 seems corrput (Compiler lacks asm-goto support)
            #return clang-11-ca2dcbd030e
            ret = "clang-11-ca2dcbd030e"
        if version == '11':
            ret = "clang-11-ca2dcbd030e"
    
    if compiler == -1:
        #filter by timestamp
        t1 = datetime.datetime(2018, 3, 1)
        t2 = datetime.datetime(2018, 4, 12)
        t3 = datetime.datetime(2018, 12, 31)
        t4 = datetime.datetime(2020, 5, 7)

        if time < t1:
            ret = "gcc-7"
        if time >= t1 and time < t2:
            #gcc-8.0.1-20180301 seems corrput (Compiler lacks asm-goto support)
            #return "gcc-8.0.1-20180301"
            ret = "gcc-8.0.1-20180412"
        if time >= t2 and time < t3:
            ret = "gcc-8.0.1-20180412"
        if time >= t3 and time < t4:
            ret = "gcc-9.0.0-20181231"
        if time >= t4:
            ret = "gcc-10.1.0-20200507"
    return ret

def make_syz_commands(text, support_enable_features, i386, repeat=True):
        command = "/tmp/syz-execprog -executor=/tmp/syz-executor "
        if text[0][:len(command)] == command:
            # If read from repro.command, text[0] was already the command
            return text[0]
        enabled = "-enable="
        normal_pm = {"arch":"amd64", "threaded":"false", "collide":"false", "sandbox":"none", "fault_call":"-1", "fault_nth":"0"}
        for line in text:
            if line.find('{') != -1 and line.find('}') != -1:
                pm = {}
                try:
                    pm = json.loads(line[1:])
                except json.JSONDecodeError:
                    pm = syzrepro_convert_format(line[1:])
                for each in normal_pm:
                    if each in pm and pm[each] != "":
                        command += "-" + each + "=" +str(pm[each]).lower() + " "
                    else:
                        if each=='arch' and i386:
                            command += "-" + each + "=386" + " "
                if "procs" in pm and str(pm["procs"]) != "1":
                    num = int(pm["procs"])
                    command += "-procs=" + str(num) + " "
                else:
                    command += "-procs=1" + " "
                if "repeat" in pm and pm["repeat"] != "":
                    if pm["repeat"] == "0" or pm["repeat"] == True:
                        command += "-repeat=" + "0 "
                    if pm["repeat"] == "1" or pm["repeat"] == False:
                        command += "-repeat=" + "1 "
                if "slowdown" in pm and pm["slowdown"] != "":
                    command += "-slowdown=" + "1 "
                #It makes no sense that limiting the features of syz-execrpog, just enable them all
                
                if support_enable_features != 2:
                    if "tun" in pm and str(pm["tun"]).lower() == "true":
                        enabled += "tun,"
                    if "binfmt_misc" in pm and str(pm["binfmt_misc"]).lower() == 'true':
                        enabled += "binfmt_misc,"
                    if "cgroups" in pm and str(pm["cgroups"]).lower() == "true":
                        enabled += "cgroups,"
                    if "close_fds" in pm and str(pm["close_fds"]).lower() == "true":
                        enabled += "close_fds,"
                    if "devlinkpci" in pm and str(pm["devlinkpci"]).lower() == "true":
                        enabled += "devlink_pci,"
                    if "netdev" in pm and str(pm["netdev"]).lower() == "true":
                        enabled += "net_dev,"
                    if "resetnet" in pm and str(pm["resetnet"]).lower() == "true":
                        enabled += "net_reset,"
                    if "usb" in pm and str(pm["usb"]).lower() == "true":
                        enabled += "usb,"
                    if "ieee802154" in pm and str(pm["ieee802154"]).lower() == "true":
                        enabled += "ieee802154,"
                    if "sysctl" in pm and str(pm["sysctl"]).lower() == "true":
                        enabled += "sysctl,"
                    if "vhci" in pm and str(pm["vhci"]).lower() == "true":
                        enabled += "vhci,"
                    if "wifi" in pm and str(pm["wifi"]).lower() == "true":
                        enabled += "wifi," 
                
                if enabled[-1] == ',':
                    command += enabled[:-1] + " testcase"
                else:
                    command += "testcase"
                break
        return command

def syzrepro_convert_format(line):
        res = {}
        p = re.compile(r'({| )(\w+):([0-9a-zA-Z-]*)')
        raw = p.sub(r'\1"\2":"\3",', line)
        if raw[raw.find('}')-1] == ',':
            new_line =raw[:raw.find('}')-1] + "}"
        else:
            new_line = raw
        if 'LegacyOptions' in new_line:
            idx = new_line.index('LegacyOptions') - 3
            new_line = new_line[:idx] + "}"
        pm = json.loads(new_line)
        for each in pm:
            if each == 'Threaded':
                res['threaded']=pm[each]
            if each == 'Collide':
                res['collide']=pm[each]
            if each == 'Repeat':
                res['repeat']=pm[each]
            if each == 'Procs':
                res['procs']=pm[each]
            if each == 'Sandbox':
                res['sandbox']=pm[each]
            if each == 'FaultCall':
                res['fault_call']=pm[each]
            if each == 'FaultNth':
                res['fault_nth']=pm[each]
            if each == 'EnableTun' or each == 'NetInjection':
                res['tun']=pm[each]
            if each == 'EnableCgroups' or each == 'Cgroups':
                res['cgroups']=pm[each]
            if each == 'UseTmpDir':
                res['tmpdir']=pm[each]
            if each == 'HandleSegv':
                res['segv']=pm[each]
            if each == 'Fault':
                res['fault']=pm[each]
            if each == 'WaitRepeat':
                res['wait_repeat']=pm[each]
            if each == 'Debug':
                res['debug']=pm[each]
            if each == 'Repro':
                res['repro']=pm[each]
            if each == 'NetDevices':
                res['netdev']=pm[each]
            if each == 'NetReset':
                res['resetnet']=pm[each]
            if each == 'BinfmtMisc':
                res['binfmt_misc']=pm[each]
            if each == 'CloseFDs':
                res['close_fds']=pm[each]
            if each == 'DevlinkPCI':
                res['devlinkpci']=pm[each]
            if each == 'USB':
                res['usb']=pm[each]
        #if len(pm) != len(res):
        #    self.logger.info("parameter is missing:\n%s\n%s", new_line, str(res))
        return res
    
def set_timer(timeout, p):
    count = 0
    while (count != timeout):
        count += 1
        sleep(1)
        if p.poll() != None:
            return
    if p.poll() is None:
        p.kill()
    return

def convert_folder_name_to_plugin_name(file):
    res = ''
    texts = file.split('_')
    for each in texts:
        res += each[0].upper() + each[1:]
    return res

def unique(seq):
    return list(set(seq))

def kasan_mem_to_shadow(addr):
    return (addr >> 3) + 0xdffffc0000000000

def clone_repo(repo_url, repo_path):
    ret = call(['git', 'clone', repo_url, repo_path])
    return ret

def local_command(command, cwd=None, shell=False, redir_err=False, logger=None):
    out = []
    if redir_err:
        p = Popen(args=command, shell=shell, cwd=cwd, stdout=PIPE, stderr=PIPE)
    else:
        p = Popen(args=command, shell=shell, cwd=cwd, stdout=PIPE, stderr=STDOUT)
    with p.stdout:
        try:
            for line in iter(p.stdout.readline, b''):
                try:
                    line = line.decode("utf-8").strip('\n').strip('\r')
                except:
                    continue
                if logger != None:
                    logger.info(line)
                out.append(line)
                #if debug:
                    #print(line)
        except ValueError:
            if p.stdout.close:
                return out
    return out

if __name__ == '__main__':
    pass

    