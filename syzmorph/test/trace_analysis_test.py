import logging, sys

from syzmorph.plugins.trace_analysis import TraceAnalysis
from syzmorph.infra.ftraceparser.trace import Trace
from .config_test import create_mini_cfg
from .syzbot_test import get_case

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
logger = logging.getLogger(__name__)
logger.setLevel(logging.NOTSET)

trace = """cpus=1
           <...>-1318  [001]    30.824950: funcgraph_entry:                   |  __x64_sys_close() {
           <...>-1318  [001]    30.824954: funcgraph_entry:                   |    __close_fd() {
           <...>-1318  [001]    30.824955: funcgraph_entry:        1.504 us   |      _raw_spin_lock();
           <...>-1318  [001]    30.824959: funcgraph_entry:                   |      filp_close() {
           <...>-1318  [001]    30.824960: funcgraph_entry:        1.361 us   |        dnotify_flush();
           <...>-1318  [001]    30.824963: funcgraph_entry:        1.401 us   |        locks_remove_posix();
           <...>-1318  [001]    30.824966: funcgraph_entry:                   |        fput() {
           <...>-1318  [001]    30.824967: funcgraph_entry:        1.409 us   |          fput_many();
           <...>-1318  [001]    30.824970: funcgraph_exit:         4.055 us   |        }
           <...>-1318  [001]    30.824971: funcgraph_exit:       + 12.285 us  |      }
           <...>-1318  [001]    30.824972: funcgraph_exit:       + 18.709 us  |    }
           <...>-1318  [001]    30.824974: funcgraph_exit:       + 24.912 us  |  }
           <...>-1318  [001]    30.826677: funcgraph_entry:                   |  __x64_sys_close() {
           <...>-1318  [001]    30.826679: funcgraph_entry:                   |    __close_fd() {
           <...>-1318  [001]    30.826681: funcgraph_entry:        1.517 us   |      _raw_spin_lock();
           <...>-1318  [001]    30.826684: funcgraph_entry:                   |      filp_close() {
           <...>-1318  [001]    30.826685: funcgraph_entry:        1.400 us   |        dnotify_flush();
           <...>-1318  [001]    30.826688: funcgraph_entry:        1.436 us   |        locks_remove_posix();
           <...>-1318  [001]    30.826691: funcgraph_entry:                   |        fput() {
           <...>-1318  [001]    30.826692: funcgraph_entry:        1.387 us   |          fput_many();
           <...>-1318  [001]    30.826695: funcgraph_exit:         4.049 us   |        }
           <...>-1318  [001]    30.826696: funcgraph_exit:       + 12.357 us  |      }
           <...>-1318  [001]    30.826698: funcgraph_exit:       + 18.224 us  |    }
           <...>-1318  [001]    30.826699: funcgraph_exit:       + 21.928 us  |  }
           <...>-1318  [001]    30.828451: funcgraph_entry:                   |  __x64_sys_close() {
           <...>-1318  [001]    30.828453: funcgraph_entry:                   |    __close_fd() {
           <...>-1318  [001]    30.828454: funcgraph_entry:        1.541 us   |      _raw_spin_lock();
           <...>-1318  [001]    30.828458: funcgraph_entry:                   |      filp_close() {
           <...>-1318  [001]    30.828459: funcgraph_entry:        1.382 us   |        dnotify_flush();
           <...>-1318  [001]    30.828462: funcgraph_entry:        1.424 us   |        locks_remove_posix();
           <...>-1318  [001]    30.828465: funcgraph_entry:                   |        fput() {
           <...>-1318  [001]    30.828466: funcgraph_entry:        1.384 us   |          fput_many();
           <...>-1318  [001]    30.828469: funcgraph_exit:         4.332 us   |        }
           <...>-1318  [001]    30.828470: funcgraph_exit:       + 12.532 us  |      }
           <...>-1318  [001]    30.828471: funcgraph_exit:       + 18.527 us  |    }
           <...>-1318  [001]    30.828473: funcgraph_exit:       + 22.432 us  |  }"""

def test_trace_analysis(hash_val, cfg):
    ana = TraceAnalysis()
    ana.prepare_on_demand()
    ana.cfg = cfg
    ana.case = get_case(hash_val)
    ana.prepare()
    return ana.run()

def test_trace_dump():
    t = Trace()
    t.load_trace(trace)
    node = t.serialize()
    node[0].dump()

def test_all(cfg):
    test_trace_dump()
    assert test_trace_analysis("97b7072a02091741ffc58f97884ab91565fd97ce", cfg), "Trace analysis didn't pass"