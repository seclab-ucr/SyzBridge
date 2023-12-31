syzbot_bug_base_url = "bug?id="
syzbot_host_url = "https://syzkaller.appspot.com/"
kasan_uaf_regx = r'KASAN: use-after-free in ([a-zA-Z0-9_]+).*'
kasan_oob_regx = r'KASAN: \w+-out-of-bounds in ([a-zA-Z0-9_]+).*'
kasan_write_regx = r'KASAN: ([a-z\\-]+) Write in ([a-zA-Z0-9_]+).*'
kasan_read_regx = r'KASAN: ([a-z\\-]+) Read in ([a-zA-Z0-9_]+).*'
kasan_write_addr_regx = r'Write of size (\d+) at addr (\w+)'
kasan_read_addr_regx = r'Read of size (\d+) at addr (\w+)'
double_free_regx = r'KASAN: double-free or invalid-free in ([a-zA-Z0-9_]+).*'
bug_desc_begin_regx = r'The buggy address belongs to the object at'
bug_desc_end_regx = r'The buggy address belongs to the page'
offset_desc_regx = r'The buggy address is located (\d+) bytes ((inside)|(to the right)|(to the left)) of'
size_desc_regx = r'which belongs to the cache [a-z0-9\-_]+ of size (\d+)'
kernel_func_def_regx= r'(^(static )?(__always_inline |const |inline )?(struct )?\w+( )?(\*)?( |\n)(([a-zA-Z0-9:_]*( |\n))?(\*)*)?([a-zA-Z0-9:_]+)\([a-zA-Z0-9*_,\(\)\[\]<>&\-\n\t ]*\))'
case_hash_syzbot_regx = r'https:\/\/syzkaller\.appspot\.com\/bug\?id=([a-z0-9]+)'
trace_regx = r'([A-Za-z0-9_.]+)(\+0x[0-9a-f]+\/0x[0-9a-f]+)?( (([A-Za-z0-9_\-.]+\/)+[A-Za-z0-9_.\-]+:\d+)( \[inline\])?)?'
source_file_regx = r'(([A-Za-z0-9_\-.]+\/)+[A-Za-z0-9_.\-]+):\d+( \[inline\])?'
startup_regx = r'Debian GNU\/Linux \d+ syzkaller ttyS\d+'
boundary_regx = r'======================================================'
call_trace_regx = r'Call Trace:'
message_drop_regx = r'printk messages dropped'
cut_here_regx = r'------------\[ cut here \]------------'
panic_regx = r'Kernel panic'
kasan_mem_regx = r'BUG: KASAN: ([a-z\\-]+) in ([a-zA-Z0-9_]+).*'
kasan_double_free_regx = r'BUG: KASAN: double-free or invalid-free in ([a-zA-Z0-9_]+).*'
kasan_write_regx = r'KASAN: ([a-z\\-]+) Write in ([a-zA-Z0-9_]+).*'
kasan_read_regx = r'KASAN: ([a-z\\-]+) Read in ([a-zA-Z0-9_]+).*'
double_free_regx = r'KASAN: double-free or invalid-free in ([a-zA-Z0-9_]+).*'
magic_regx = r'\?!\?MAGIC\?!\?read->(\w*) size->(\d*)'
write_regx = r'Write of size (\d+) at addr (\w*)'
read_regx = r'Read of size (\d+) at addr (\w*)'
syscall_data_path = 'resources/syscalls.txt'