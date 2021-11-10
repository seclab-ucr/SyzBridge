import logging, sys

from syzmorph.plugins.failure_analysis import FailureAnalysis
from .config_test import create_mini_cfg

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
logger = logging.getLogger(__name__)
logger.setLevel(logging.NOTSET)

normal_kasan_report = """
netdevsim netdevsim0 netdevsim1: set [1, 0] type 2 family 0 port 6081 - 0
netdevsim netdevsim0 netdevsim2: set [1, 0] type 2 family 0 port 6081 - 0
netdevsim netdevsim0 netdevsim3: set [1, 0] type 2 family 0 port 6081 - 0
==================================================================
BUG: KASAN: use-after-free in memcpy include/linux/string.h:447 [inline]
BUG: KASAN: use-after-free in skb_copy_from_linear_data_offset include/linux/skbuff.h:3676 [inline]
BUG: KASAN: use-after-free in skb_segment+0x14ba/0x37a0 net/core/skbuff.c:3996
Read of size 2324 at addr ffff88801a8ff2f7 by task syz-executor061/8471

CPU: 0 PID: 8471 Comm: syz-executor061 Not tainted 5.11.0-rc3-syzkaller #0
Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 01/01/2011
Call Trace:
 __dump_stack lib/dump_stack.c:79 [inline]
 dump_stack+0x107/0x163 lib/dump_stack.c:120
 print_address_description.constprop.0.cold+0x5b/0x2f8 mm/kasan/report.c:230
 __kasan_report mm/kasan/report.c:396 [inline]
 kasan_report.cold+0x79/0xd5 mm/kasan/report.c:413
 check_memory_region_inline mm/kasan/generic.c:179 [inline]
 check_memory_region+0x13d/0x180 mm/kasan/generic.c:185
 memcpy+0x20/0x60 mm/kasan/shadow.c:64
 memcpy include/linux/string.h:447 [inline]
 skb_copy_from_linear_data_offset include/linux/skbuff.h:3676 [inline]
 skb_segment+0x14ba/0x37a0 net/core/skbuff.c:3996
 udp4_ufo_fragment+0x4ae/0x700 net/ipv4/udp_offload.c:363
 inet_gso_segment+0x502/0x1110 net/ipv4/af_inet.c:1378
 skb_mac_gso_segment+0x26e/0x530 net/core/dev.c:3326
 __skb_gso_segment+0x330/0x6e0 net/core/dev.c:3399
 skb_gso_segment include/linux/netdevice.h:4708 [inline]
 validate_xmit_skb+0x69e/0xee0 net/core/dev.c:3644
 __dev_queue_xmit+0x988/0x2dd0 net/core/dev.c:4142
 packet_snd net/packet/af_packet.c:3006 [inline]
 packet_sendmsg+0x2406/0x52a0 net/packet/af_packet.c:3031
 sock_sendmsg_nosec net/socket.c:652 [inline]
 sock_sendmsg+0xcf/0x120 net/socket.c:672
 __sys_sendto+0x21c/0x320 net/socket.c:1975
 __do_sys_sendto net/socket.c:1987 [inline]
 __se_sys_sendto net/socket.c:1983 [inline]
 __x64_sys_sendto+0xdd/0x1b0 net/socket.c:1983
 do_syscall_64+0x2d/0x70 arch/x86/entry/common.c:46
 entry_SYSCALL_64_after_hwframe+0x44/0xa9
RIP: 0033:0x4436e9
Code: 18 89 d0 c3 66 2e 0f 1f 84 00 00 00 00 00 0f 1f 00 48 89 f8 48 89 f7 48 89 d6 48 89 ca 4d 89 c2 4d 89 c8 4c 8b 4c 24 08 0f 05 <48> 3d 01 f0 ff ff 0f 83 eb 0d fc ff c3 66 2e 0f 1f 84 00 00 00 00
RSP: 002b:00007fffe7591c98 EFLAGS: 00000246 ORIG_RAX: 000000000000002c
RAX: ffffffffffffffda RBX: 0000000000000003 RCX: 00000000004436e9
RDX: 000000000000fc13 RSI: 0000000020000280 RDI: 0000000000000003
RBP: 00007fffe7591cb0 R08: 0000000000000000 R09: 000000000000002f
R10: 0000000000000800 R11: 0000000000000246 R12: 00007fffe7591cc0
R13: 0000000000000000 R14: 0000000000000000 R15: 0000000000000000

Allocated by task 6431:
 kasan_save_stack+0x1b/0x40 mm/kasan/common.c:38
 kasan_set_track mm/kasan/common.c:46 [inline]
 set_alloc_info mm/kasan/common.c:401 [inline]
 ____kasan_kmalloc.constprop.0+0x82/0xa0 mm/kasan/common.c:429
 kasan_slab_alloc include/linux/kasan.h:205 [inline]
 slab_post_alloc_hook mm/slab.h:512 [inline]
 slab_alloc_node mm/slub.c:2891 [inline]
 slab_alloc mm/slub.c:2899 [inline]
 kmem_cache_alloc+0x1c6/0x440 mm/slub.c:2904
 getname_flags.part.0+0x50/0x4f0 fs/namei.c:138
 getname_flags include/linux/audit.h:319 [inline]
 getname+0x8e/0xd0 fs/namei.c:209
 do_sys_openat2+0xf5/0x420 fs/open.c:1166
 do_sys_open fs/open.c:1188 [inline]
 __do_sys_open fs/open.c:1196 [inline]
 __se_sys_open fs/open.c:1192 [inline]
 __x64_sys_open+0x119/0x1c0 fs/open.c:1192
 do_syscall_64+0x2d/0x70 arch/x86/entry/common.c:46
 entry_SYSCALL_64_after_hwframe+0x44/0xa9

Freed by task 6431:
 kasan_save_stack+0x1b/0x40 mm/kasan/common.c:38
 kasan_set_track+0x1c/0x30 mm/kasan/common.c:46
 kasan_set_free_info+0x20/0x30 mm/kasan/generic.c:356
 ____kasan_slab_free+0xe1/0x110 mm/kasan/common.c:362
 kasan_slab_free include/linux/kasan.h:188 [inline]
 slab_free_hook mm/slub.c:1547 [inline]
 slab_free_freelist_hook+0x5d/0x150 mm/slub.c:1580
 slab_free mm/slub.c:3142 [inline]
 kmem_cache_free+0x82/0x350 mm/slub.c:3158
 putname+0xe1/0x120 fs/namei.c:259
 do_sys_openat2+0x153/0x420 fs/open.c:1181
 do_sys_open fs/open.c:1188 [inline]
 __do_sys_open fs/open.c:1196 [inline]
 __se_sys_open fs/open.c:1192 [inline]
 __x64_sys_open+0x119/0x1c0 fs/open.c:1192
 do_syscall_64+0x2d/0x70 arch/x86/entry/common.c:46
 entry_SYSCALL_64_after_hwframe+0x44/0xa9

The buggy address belongs to the object at ffff88801a8fe600
 which belongs to the cache names_cache of size 4096
The buggy address is located 3319 bytes inside of
 4096-byte region [ffff88801a8fe600, ffff88801a8ff600)
The buggy address belongs to the page:
page:0000000036b7a58f refcount:1 mapcount:0 mapping:0000000000000000 index:0x0 pfn:0x1a8f8
head:0000000036b7a58f order:3 compound_mapcount:0 compound_pincount:0
flags: 0xfff00000010200(slab|head)
raw: 00fff00000010200 0000000000000000 0000000500000001 ffff8880101be140
raw: 0000000000000000 0000000000070007 00000001ffffffff 0000000000000000
page dumped because: kasan: bad access detected

Memory state around the buggy address:
 ffff88801a8ff180: fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb
 ffff88801a8ff200: fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb
>ffff88801a8ff280: fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb
                                                             ^
 ffff88801a8ff300: fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb
 ffff88801a8ff380: fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb
==================================================================
"""

failed_kasan_report = """
------------[ cut here ]------------
refcount_t: addition on 0; use-after-free.
WARNING: CPU: 1 PID: 4133 at lib/refcount.c:25 refcount_warn_saturate+0x13d/0x1a0 lib/refcount.c:25
Kernel panic - not syncing: panic_on_warn set ...
CPU: 1 PID: 4133 Comm: kworker/u4:8 Not tainted 5.9.0-rc6-syzkaller #0
Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 01/01/2011
Workqueue: qrtr_ns_handler qrtr_ns_worker
Call Trace:
 __dump_stack lib/dump_stack.c:77 [inline]
 dump_stack+0x1d6/0x29e lib/dump_stack.c:118
 panic+0x2c0/0x800 kernel/panic.c:231
 __warn+0x227/0x250 kernel/panic.c:600
 report_bug+0x1b1/0x2e0 lib/bug.c:198
 handle_bug+0x42/0x80 arch/x86/kernel/traps.c:234
 exc_invalid_op+0x16/0x40 arch/x86/kernel/traps.c:254
 asm_exc_invalid_op+0x12/0x20 arch/x86/include/asm/idtentry.h:536
RIP: 0010:refcount_warn_saturate+0x13d/0x1a0 lib/refcount.c:25
Code: c7 03 f4 37 89 31 c0 e8 01 5f 88 fd 0f 0b eb a3 e8 c8 bf b6 fd c6 05 1a 33 ed 05 01 48 c7 c7 3a f4 37 89 31 c0 e8 e3 5e 88 fd <0f> 0b eb 85 e8 aa bf b6 fd c6 05 fd 32 ed 05 01 48 c7 c7 66 f4 37
RSP: 0018:ffffc900072f79c0 EFLAGS: 00010046
RAX: 1ceabb8756dc6c00 RBX: 0000000000000002 RCX: ffff8880a3208300
RDX: 0000000000000000 RSI: 0000000080000001 RDI: 0000000000000000
RBP: 0000000000000002 R08: ffffffff815e37c0 R09: ffffed1015d241c3
R10: ffffed1015d241c3 R11: 0000000000000000 R12: ffff888096c23098
R13: 1ffff1101454b39e R14: 0000000000000282 R15: ffff888096c23000
 refcount_add include/linux/refcount.h:206 [inline]
 refcount_inc include/linux/refcount.h:241 [inline]
 kref_get include/linux/kref.h:45 [inline]
 qrtr_node_acquire net/qrtr/qrtr.c:196 [inline]
 qrtr_node_lookup+0xc0/0xd0 net/qrtr/qrtr.c:388
 qrtr_send_resume_tx net/qrtr/qrtr.c:980 [inline]
 qrtr_recvmsg+0x429/0xa80 net/qrtr/qrtr.c:1043
 qrtr_ns_worker+0x176/0x45f0 net/qrtr/ns.c:624
 process_one_work+0x789/0xfc0 kernel/workqueue.c:2269
 worker_thread+0xaa4/0x1460 kernel/workqueue.c:2415
 kthread+0x37e/0x3a0 drivers/block/aoe/aoecmd.c:1234
 ret_from_fork+0x1f/0x30 arch/x86/entry/entry_64.S:294
Shutting down cpus with NMI
Kernel Offset: disabled
Rebooting in 86400 seconds..

"""

def test_module_check1():
    #CONFIG_INET
    cfg = create_mini_cfg()
    fa = FailureAnalysis()
    fa.prepare_on_demand(normal_kasan_report)
    fa.cfg = cfg
    return fa.module_check("net/ipv4/udp_offload.c")

def test_module_check2():
    #CONFIG_QRTR
    cfg = create_mini_cfg()
    fa = FailureAnalysis()
    fa.prepare_on_demand(normal_kasan_report)
    fa.cfg = cfg
    return fa.module_check("net/qrtr/qrtr.c")

def test_module_check3():
    #CONFIG_QRTR
    cfg = create_mini_cfg()
    fa = FailureAnalysis()
    fa.prepare_on_demand(normal_kasan_report)
    fa.cfg = cfg
    return fa.module_check("arch/x86/entry/common.c")

def test_module_check4():
    cfg = create_mini_cfg()
    fa = FailureAnalysis()
    fa.prepare_on_demand(normal_kasan_report)
    fa.cfg = cfg
    return fa.run()

def test_module_check5():
    cfg = create_mini_cfg()
    fa = FailureAnalysis()
    fa.prepare_on_demand(failed_kasan_report)
    fa.cfg = cfg
    return fa.run()

def test_all():
    assert test_module_check1(), "Can not locate CONFIG_INET"
    assert (not test_module_check2()), "WTF, they shouldn't enable CONFIG_QRTR"
    assert test_module_check3(), "Can not locate do_syscall_64"
    assert test_module_check4(), "Can not pass normal_kasan_report"
    assert (not test_module_check5()), "WTF, thery shouldn't pass failed_kasan_report"