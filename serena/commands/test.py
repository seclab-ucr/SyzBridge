import importlib
import logging

from serena.commands import Command

logger = logging.getLogger(__name__)

class TestCommand(Command):
    def __init__(self, parser):
        super().__init__()
        self.add_arguments(parser)

    def add_arguments(self, parser):
        parser.add_argument('--all',  action='store_true', help='test all modules')
        parser.add_argument('--config',  action='store_true', help='test config module')

    def run(self, args):
        if args.all:
            self.test_all()
        else:
            if args.config:
                self.test_target('config')
    
    def test_target(self, name):
        try:
            module = importlib.import_module("serena.test.{}_test".format(name))
        except ModuleNotFoundError:
            logger.error("serena.test.{}_test module not found".format(name))
            return
        self._test(module)

    def _test(self, module):
        test_all_func = getattr(module, "test_all")
        test_all_func()
