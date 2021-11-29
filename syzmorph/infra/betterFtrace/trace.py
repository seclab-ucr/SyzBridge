from logging import StreamHandler
from os import write
import progressbar

from syzmorph.infra.tool_box import *
from syzmorph.infra.strings import *
from .node import Node
from .error import NodeTextError

class Trace:
    def __init__(self, logger=None, debug=False):
        self.trace_text = None
        self.n_cpu = 0
        self.n_task = 0
        self.node = []
        self.index2node = {}
        self.begin_node = {}
        self.logger = logger
        self.debug = debug
        if self.logger == None:
           self.logger = init_logger(__name__, debug=self.debug, propagate=self.debug, handler_type=STREAM_HANDLER)
    
    def load_tracefile(self, trace_file):
        with open(trace_file, 'r') as f:
            self.trace_text = f.readlines()
        
    def load_trace(self, trace_text):
        if type(trace_text) == str:
            self.trace_text = trace_text.split('\n')
        else:
            self.trace_text = trace_text
    
    def serialize(self):
        if self.trace_text == []:
            raise ValueError('Trace is empty')
        
        parents = {}
        self.begin_node = []
        self.trace_text[0]
        start = 0
        total_line = len(self.trace_text)

        for i in range(start, total_line):
            if regx_match(r'CPU (\d+) is empty', self.trace_text[i]):
                continue
            start = i
            break
        self.n_cpu = int(regx_get(r'cpus=(\d+)', self.trace_text[start], 0))
        node = Node(self.trace_text[start+1])
        self.node.append(node)
        self.index2node[node] = 1
        parents[node.pid] = node
        self.begin_node.append(node)

        if node is None:
            raise ValueError('Trace is not valid')
        #bar = Bar('Processing', max=total_line)
        widgets=[
            ' [Serializing trace report] ',
            progressbar.Bar(),
            ' (', progressbar.Percentage(),' | ', progressbar.ETA(), ') ',
        ]
        for i in progressbar.progressbar(range(start+2, total_line), widgets=widgets):
            line = self.trace_text[i].strip()

            try:
                child = Node(line)
            except NodeTextError:
                self.logger.error("Invalid node format {}".format(line))
                continue
            self.node.append(child)
            self.index2node[child] = i
            if child.pid in parents:
                parents[child.pid].add_node(child)
            else:
                self.begin_node.append(child)
            parents[child.pid] = child

        self.n_task = len(self.begin_node)
        return self.begin_node

    def find_node(self, time_stamp, cpu):
        for node in self.node:
            if node.time_stamp == time_stamp and cpu == node.cpu:
                return node
        return None
    
    def dump_to_json(self, file_name):
        with open(file_name, 'w') as f:
            widgets=[
                ' [Caching trace data] ',
                progressbar.Bar(),
                ' (', progressbar.Percentage(),' | ', progressbar.ETA(), ') ',
            ]
            for i in progressbar.progressbar(range(0, len(self.node)), widgets=widgets):
                each = self.node[i]
                f.writelines(json.dumps(each, default=self._dump_node_to_json, sort_keys=True, indent=4, check_circular=False)+'\n')
                f.write(boundary_regx+'\n')
            f.writelines(json.dumps(self, default=self._dump_trace_to_json, sort_keys=True, indent=4, check_circular=False)+'\n')
            f.close()
    
    def _dump_node_to_json(self, o):
        if type(o.next_node) == Node:
            o.next_node = self.index2node[o.next_node]
        if type(o.next_sibling) == Node:
            o.next_sibling = self.index2node[o.next_sibling]
        if type(o.scope_begin_node) == Node:
            o.scope_begin_node = self.index2node[o.scope_begin_node]
        if type(o.scope_end_node) == Node:
            o.scope_end_node = self.index2node[o.scope_end_node]
        if type(o.parent) == Node:
            o.parent = self.index2node[o.parent]
        for i in range(0, len(o.children)):
            o.children[i] = self.index2node[o.children[i]]
        return o.__dict__
    
    def _dump_trace_to_json(self, o):
        for i in range(0, len(o.node)):
            o.node[i] = o.index2node[o.node[i]]
        for i in range(0, len(o.begin_node)):
            o.begin_node[i] = o.index2node[o.begin_node[i]]
        o.index2node = {}
        return o.__dict__
            