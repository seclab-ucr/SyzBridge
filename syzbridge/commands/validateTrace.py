import importlib

from infra.error import *
from infra.tool_box import *
from syzbridge.commands import Command

class ValidateTraceCommand(Command):
    def __init__(self):
        super().__init__()
        self.entry_func = None
        self.dest_func = None
        self.trace_file = None
        self.args = None
        self.trace_map = {}

    def add_arguments(self, parser):
        super().add_arguments(parser)
        parser.add_argument('--entry-func',  nargs='+', action='store', help='start from this entry function')
        parser.add_argument('--dest-func', nargs='+', action='store', help='end at this dest function')
        parser.add_argument('--trace', nargs='+', action='store', help='trace file')

    def custom_subparser(self, parser, cmd):
        return parser.add_parser(cmd, help='Validate a proper trace with concrete arguments')

    def run(self, args):
        self.args = args
        self.entry_func = self.args.entry_func[0]
        self.dest_func = self.args.dest_func[0]
        self.trace_file = self.args.trace_file[0]
        self.open_trace_file()
        self.run_validation()

    def run_validation(self):
        self.get_plugin_class("trace_validation")
    
    def get_plugin_class(self, plugin_name):
        module = importlib.import_module("plugins.{}".format(plugin_name))
        enable = module.ENABLE
        if not enable:
            return None
        class_name = convert_folder_name_to_plugin_name(plugin_name)
        new_class = getattr(module, class_name)
        A = new_class()
        return A

    def open_trace_file(self):
        with open(self.trace_file, "r") as f:
            text = f.readlines()
            for line in text:
                funcs = line.split('->')
                if self.entry_func in funcs and self.dest_func in funcs:
                    self.parse_trace(funcs)
    
    def parse_trace(self, funcs):
        started = False
        prev_func = None
        for each in funcs:
            if each == self.entry_func:
                started = True
                prev_func = each
                continue
            if each == self.dest_func:
                return
            if started:
                if prev_func not in self.trace_map:
                    self.trace_map[prev_func] = []
                if each not in self.trace_map[prev_func]:
                    self.trace_map[prev_func].append(each)
            
