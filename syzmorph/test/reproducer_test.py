import logging
from syzmorph.modules.reproducer import Reproducer

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
logger = logging.getLogger(__name__)
logger.setLevel(logging.NOTSET)

def get_reproducer(cfg):
    repro = Reproducer(cfg=cfg, path_linux=self.path_linux, path_case=self.path_case, path_syzmorph=self.path_syzmorph, 
            ssh_port=cfg.ssh_port, case_logger=logger, debug= True)
    return repro