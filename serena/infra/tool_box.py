import os, re, stat, sys
import requests
import logging
import random

from .strings import *

FILE_HANDLER = 0
STREAM_HANDLER = 1

KASAN_NONE=0
KASAN_OOB=1
KASAN_UAF=2

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
        return offset, size
    if bug_type == KASAN_NONE:
        return offset, size
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
                return offset, size
            line = bug_desc[0]
            addr_begin = regx_get(r'The buggy address belongs to the object at \w+', line, 0)
            if addr_begin != None:
                addr_begin = int(addr_begin, 16)
                offset = bug_mem_addr - addr_begin
        if size == None:
            size = offset
    return offset, size

def extrace_call_trace(report):
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
        if regx_match(r'Call Trace', line):
            record_flag = 1
            res = []
        if record_flag == 1 and regx_match_list(call_trace_end, line):
            record_flag ^= 1
            break
    return res

def chmodX(path):
    st = os.stat(path)
    os.chmod(path, st.st_mode | stat.S_IEXEC)

def request_get(url):
    return requests.request(method='GET', url=url)

def init_logger(logger_id, cus_format='%(message)s', debug=False, propagate=False, handler_type = FILE_HANDLER):
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

if __name__ == '__main__':
    pass

    