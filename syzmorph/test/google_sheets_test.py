import logging, sys

from syzmorph.plugins.google_sheets import GoogleSheets
from .config_test import create_mini_cfg
from .syzbot_test import get_case

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
logger = logging.getLogger(__name__)
logger.setLevel(logging.NOTSET)


def test_trace_analysis(hash_val):
    cfg = create_mini_cfg()
    ana = GoogleSheets()
    ana.cfg = cfg
    ana.case = get_case(hash_val)
    ana.prepare_on_demand("./google_sheet.json", "open_uaf_oob_16-12-2021")
    return ana.run()

def test_all():
    test_trace_analysis('a8ab28e7a5cdf8e3a84043b32cc4d3c5db8c22d3')
    #test_trace_analysis("97b7072a02091741ffc58f97884ab91565fd97ce")