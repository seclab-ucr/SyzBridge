import logging, sys

from syzmorph.modules.analyzor.trace_analysis import TraceAnalysis
from .config_test import create_mini_cfg
from .syzbot_test import get_case

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
logger = logging.getLogger(__name__)
logger.setLevel(logging.NOTSET)

def test_trace_analysis(hash_val):
    cfg = create_mini_cfg()
    ana = TraceAnalysis()
    ana.prepare_on_demand()
    ana.cfg = cfg
    ana.case = get_case(hash_val)
    ana.prepare()
    return ana.run()

def test_all():
    test_trace_analysis("97b7072a02091741ffc58f97884ab91565fd97ce")