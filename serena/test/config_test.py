import json
import logging

from serena.infra.config import Config

logger = logging.getLogger(__name__)

config_normal = """
{
    "vendor_image":"/home/xzou017/projects/BugReproducing/tools/images/ubuntu-20.04.img",
    "ssh_key":"/home/xzou017/projects/BugReproducing/tools/images/id_rsa",
    "ssh_port":3778,
    "max_retrieval":1000,
    "max_parallel":8,
    "vendor_src":"/home/xzou017/projects/ubuntu-focal/ubuntu-focal",
    "vendor_name":"Ubuntu"
}
"""

config_unrecognized_key = """
{
    "vendor_image":"/home/xzou017/projects/BugReproducing/tools/images/ubuntu-20.04.img",
    "ssh_key":"/home/xzou017/projects/BugReproducing/tools/images/id_rsa",
    "ssh_port":3778,
    "max_retrieval":1000,
    "max_parallel":8,
    "vendor_src":"/home/xzou017/projects/ubuntu-focal/ubuntu-focal",
    "vendor_name":"Ubuntu",
    "wrongkey":"xxx"
}
"""

config_wrong_type = """
{
    "vendor_image":1234,
    "ssh_key":"/home/xzou017/projects/BugReproducing/tools/images/id_rsa",
    "ssh_port":3778,
    "max_retrieval":1000,
    "max_parallel":8
}
"""

def create_mini_cfg():
    cfg = Config()
    cfg.load(json.loads(config_normal))
    return cfg

def test_config_normal():
    cfg = Config()
    cfg.load(json.loads(config_normal))

def test_config_unrecognized_key():
    cfg = Config()
    cfg.load(json.loads(config_unrecognized_key))

def test_wrong_type():
    cfg = Config()
    cfg.load(json.loads(config_wrong_type))

def test_all():
    try:
        test_config_normal()
    except Exception as e:
        logger.error("test_config_normal failed: {}".format(e))

    try:
        test_config_unrecognized_key()
    except Exception as e:
        logger.error("test_config_unrecognized_key failed: {}".format(e))

    try:
        test_wrong_type()
    except Exception as e:
        logger.error("test_wrong_type failed: {}".format(e))

