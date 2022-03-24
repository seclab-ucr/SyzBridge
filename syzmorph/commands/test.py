import importlib
import logging
import os

from infra.error import *
from syzmorph.commands import Command

logger = logging.getLogger(__name__)

class TestCommand(Command):
    def __init__(self):
        super().__init__()

    def add_arguments(self, parser):
        super().add_arguments(parser)
        parser.add_argument('--all',  action='store_true', help='test all modules')
        parser.add_argument('--config', nargs='?', action='store', help='config file.')
        
        self.add_arguments_for_plugins(parser)

    def custom_subparser(self, parser, cmd):
        return parser.add_parser(cmd, help='Modular test (Debug only)')
    
    def parse_config(self, config):
        from syzmorph.infra.config.config import Config
        
        cfg = Config()
        cfg.load_from_file(config)

        return cfg
    
    def add_arguments_for_plugins(self, parser):
        proj_dir = os.path.join(os.getcwd(), "syzmorph")
        modules_dir = os.path.join(proj_dir, "plugins")
        module_folder = [ cmd for cmd in os.listdir(modules_dir)
                    if not cmd.endswith('.py') and not cmd == "__pycache__" ]
        for module_name in module_folder:
            try:
                module = importlib.import_module("plugins.{}".format(module_name))
                enable = module.ENABLE
                if not enable:
                    continue
                help_msg = "TEST " + module.DESCRIPTION
                t = module_name.split('_')
                cmd_msg = '--' + '-'.join(t)
                parser.add_argument(cmd_msg, action='store_true', help=help_msg)
            except Exception as e:
                print("Fail to load plugin {}: {}".format(module_name, e))
                continue

    def run(self, args):
        try:
            if args.config != None:
                self.cfg = self.parse_config(args.config)
            else:
                print("--config is necessary")
                return
        except TargetFileNotExist as e:
            logger.error(e)
            return
        except ParseConfigError as e:
            logger.error(e)
            return
        except TargetFormatNotMatch as e:
            logger.error(e)
            return

        if args.all:
            self.test_all()
        else:
            for key in args.__dict__:
                if getattr(args, key) and type(getattr(args, key)) == bool:
                    self.test_target(key)
    
    def test_target(self, name):
        try:
            module = importlib.import_module("syzmorph.test.{}_test".format(name))
        except ModuleNotFoundError:
            logger.error("syzmorph.test.{}_test module not found".format(name))
            return
        self._test(module)

    def _test(self, module):
        test_all_func = getattr(module, "test_all")
        test_all_func(self.cfg)
