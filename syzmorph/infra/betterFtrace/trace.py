import progressbar

from syzmorph.infra.tool_box import regx_get, regx_kasan_line, regx_match, init_logger
from .node import Node
from .error import NodeTextError

class Trace:
    def __init__(self, logger=None, debug=False):
        self.trace_text = None
        self.n_cpu = 0
        self.n_task = 0
        self.node = []
        self.begin_node = {}
        self.logger = logger
        self.debug = debug
        if self.logger == None:
           self.logger = init_logger(__name__, debug=self.debug, propagate=self.debug)

    
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
        self.n_cpu = int(regx_get(r'cpus=(\d+)', self.trace_text[0], 0))
        node = Node(self.trace_text[1])
        self.node.append(node)
        parents[node.pid] = node
        self.begin_node.append(node)
        percentage = 0

        if node is None:
            raise ValueError('Trace is not valid')
        total_line = len(self.trace_text)
        #bar = Bar('Processing', max=total_line)
        widgets=[
            ' [Serializing trace file] ',
            progressbar.Bar(),
            ' (', progressbar.Percentage(), ') ',
        ]
        for i in progressbar.progressbar(range(1, total_line), widgets=widgets):
            line = self.trace_text[i].strip()

            try:
                child = Node(line)
            except NodeTextError:
                self.logger.error("Invalid node format {}".format(line))
                continue
            self.node.append(child)
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
            