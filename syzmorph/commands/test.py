import importlib
import logging

from syzmorph.commands import Command

logger = logging.getLogger(__name__)

class TestCommand(Command):
    def __init__(self):
        super().__init__()

    def add_arguments(self, parser):
        super().add_arguments(parser)
        parser.add_argument('--all',  action='store_true', help='test all modules')
        parser.add_argument('--config',  action='store_true', help='test config module')
        parser.add_argument('--failure-analysis',  action='store_true', help='test failure_analysis module')
        parser.add_argument('--lts-analysis', action='store_true', help='test lts_analysis module')
        parser.add_argument('--bug-reproduce', action='store_true', help='test bug_reproduce module')
        parser.add_argument('--trace-analysis', action='store_true', help='test trace_analysis module')

    def custom_subparser(self, parser, cmd):
        return parser.add_parser(cmd, help='Modular test (Debug only)')

    def run(self, args):
        if args.all:
            self.test_all()
        else:
            if args.config:
                self.test_target('config')
            if args.lts_analysis:
                self.test_target('lts_analysis')
            if args.bug_reproduce:
                self.test_target('bug_reproduce')
            if args.trace_analysis:
                self.test_target('trace_analysis')
    
    def test_target(self, name):
        try:
            module = importlib.import_module("syzmorph.test.{}_test".format(name))
        except ModuleNotFoundError:
            logger.error("syzmorph.test.{}_test module not found".format(name))
            return
        self._test(module)

    def _test(self, module):
        test_all_func = getattr(module, "test_all")
        test_all_func()
