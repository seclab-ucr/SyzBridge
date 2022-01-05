from logging import StreamHandler
from os import write
import progressbar

from .tool_box import *
from .strings import *
from .node import Node
from .error import *
from console import fg, bg, fx


class Trace:
    def __init__(self, logger=None, debug=False, as_servicve=False):
        self.trace_text = None
        self.n_cpu = 0
        self.n_task = 0
        self.node = []
        self.blacklist = []
        self.index2node = {}
        self.begin_node = {}
        self.filter_list = ['pid', 'cpu', 'task', 'time_stamp', 'event', 'entry']
        self.filter = {}
        self.logger = logger
        self.debug = debug
        self.as_servicve = as_servicve
        self.remove_filter_all()
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
        node_id = 0
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
        try:
            self.n_cpu = int(regx_get(r'cpus=(\d+)', self.trace_text[start], 0))
        except TypeError:
            raise TraceParseError('CPU number is not found')
        last_node = Node(self.trace_text[start+1], node_id)
        self.node.append(last_node)
        self.index2node[node_id] = last_node
        parents[last_node.pid] = last_node
        self.begin_node.append(last_node)
        node_id += 1

        if last_node is None:
            raise ValueError('Trace is not valid')
        #bar = Bar('Processing', max=total_line)
        widgets=[
            ' [Serializing trace report] ',
            progressbar.Bar(),
            ' (', progressbar.Percentage(),' | ', progressbar.ETA(), ') ',
        ]

        if self.as_servicve:
            it = range(start+2, total_line)
        else:
            it = progressbar.progressbar(range(start+2, total_line), widgets=widgets)
        for i in it:
            line = self.trace_text[i].strip()

            try:
                child = Node(line, node_id)
            except NodeTextError:
                self.logger.error("Invalid node format {}".format(line))
                continue
            last_node.next_node_by_time = child
            child.prev_node_by_time = last_node
            last_node = child
            self.node.append(child)
            self.index2node[node_id] = last_node
            node_id += 1
            if child.pid in parents:
                parents[child.pid].add_node(child)
            else:
                self.begin_node.append(child)
            parents[child.pid] = child

        self.n_task = len(self.begin_node)
        return self.begin_node
    
    def show_filters(self):
        for filter_name in self.filter_list:
            if self.filter[filter_name] != None:
                self.logger.info('Filter: {}=={}'.format(filter_name, self.filter[filter_name]))
    
    def add_filter(self, filter_name, filter_expr):
        if filter_name in self.filter_list:
            self.filter[filter_name].append(filter_expr)
            return len(self.filter[filter_name]) - 1
    
    def remove_filter_all(self):
        for filter_name in self.filter_list:
            self.remove_filter(filter_name)

    def remove_filter(self, filter_name):
        if filter_name in self.filter_list:
            self.filter[filter_name] = []
    
    def remove_filter_inst(self, filter_name, index):
        if filter_name in self.filter_list:
            try:
                self.filter[filter_name].pop(index)
            except IndexError:
                self.logger.error('Index out of range')
    
    def is_filtered(self, node):
        for key in self.filter:
            for expr in self.filter[key]:
                if key == 'entry':
                    hop = self.get_hops_from_entry_node(node)
                    entry_node = self.find_node(hop.pop())
                    if not eval('\"{}\"{}'.format(getattr(entry_node, 'id'), expr)) \
                       and not eval('\"{}\"{}'.format(getattr(entry_node, 'function_name'), expr)):
                        return True
                elif key == 'pid' or key == 'cpu':
                    if not eval('{}{}'.format(getattr(node, key), expr)):
                        return True
                elif not eval('\"{}\"{}'.format(getattr(node, key), expr)):
                        return True
        return False
    
    def get_hops_from_entry_node(self, node):
        hop = [node.id]
        while node.parent != None:
            node = node.parent
            hop.append(node.id)
        return hop

    def find_node(self, node_id: int):
        if node_id in self.index2node:
                return self.index2node[node_id]
        return None
    
    def find_info(self, info, find_all=False, start_node=None):
        res = []
        if start_node != None:
            bnode = start_node.next_node_by_time
        else:
            bnode = self.begin_node[0]
        while bnode != None:
                if bnode.info.find(info) != -1:
                    if not self.is_filtered(bnode):
                        res.append(bnode)
                        if not find_all:
                            return res
                bnode = bnode.next_node_by_time
        return res
    
    def print_banner(self):
        banner = "id{}|task{}| pid{} | cpu{}| time stamp: event".format((10-len('id'))*' ', (15-len('task'))*' ', (10-len('pid'))*' ', (7-len('cpu'))*' ')
        align = ' ' * (91 - len(banner))
        banner += align + '| info'
        print(banner)
    
    def print_cpu_banner(self):
        banner = '|'
        for i in range(self.n_cpu):
            banner += ' CPU {} |'.format(i)
        print(banner)
    
    def print_node(self, node, highlight=False, trim_bracket=False, warn_when_filtered=False):
        if node is None:
            print('Content has been truncated. This trace did not finish before killing the process.')
            return
        if self.is_filtered(node):
            if warn_when_filtered:
                self.logger.warning('some nodes are filtered')
            return
        data = node.text.split('|')
        align = 10 - len(str(node.id))
        if highlight:
            header = "{}{}|{}".format(fg.lightmagenta(str(node.id)), align*' ', fg.red(node.text))
        else:
            header = "{}{}|{}|{}|{}|{}{}".format(fg.lightmagenta(str(node.id)), align*' ', fg.yellow(data[0]), fg.black(data[1]), fg.cyan(data[2]), fg.green(data[3]), fg.blue('|'+'|'.join((data[4:]))))
        if trim_bracket:
            header = header[:header.find('{')] + ';'
        print(header)
    
    def print_trace(self, start_node, level=0, length=30, end_node=None):
        if length <= 0 or start_node == None:
            return length
        if start_node.function_name in self.blacklist:
            return self.print_trace(start_node.next_sibling, level, length, end_node)
        self.print_node(start_node, trim_bracket=(level == 0 and start_node.children != []), warn_when_filtered=False)
        if end_node != None and start_node.id == end_node.id:
            return 0
        length -= 1
        if level > 0:
            if len(start_node.children) > 0:
                length = self.print_trace(start_node.children[0], level-1, length, end_node)

        if length > 0:
            if start_node.is_function and start_node.is_root and level>0:
                self.print_node(start_node.scope_end_node)
                length -= 1
                if end_node != None and start_node.scope_end_node.id == end_node.id:
                    return 0
        
        length = self.print_trace(start_node.next_sibling, level, length, end_node)
        return length
    
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
        if type(o.prev_node) == Node:
            o.prev_node = o.prev_node.id
        if type(o.next_node) == Node:
            o.next_node = o.next_node.id
        if type(o.prev_sibling) == Node:
            o.prev_sibling = o.prev_sibling.id
        if type(o.next_sibling) == Node:
            o.next_sibling = o.next_sibling.id
        if type(o.scope_begin_node) == Node:
            o.scope_begin_node = o.scope_begin_node.id
        if type(o.scope_end_node) == Node:
            o.scope_end_node = o.scope_end_node.id
        if type(o.parent) == Node:
            o.parent = o.parent.id
        if type(o.prev_node_by_time) == Node:
            o.prev_node_by_time = o.prev_node_by_time.id
        if type(o.next_node_by_time) == Node:
            o.next_node_by_time = o.next_node_by_time.id
        for i in range(0, len(o.children)):
            o.children[i] = o.children[i].id
        return o.__dict__
    
    def _dump_trace_to_json(self, o):
        for i in range(0, len(o.node)):
            o.node[i] = o.node[i].id
        for i in range(0, len(o.begin_node)):
            o.begin_node[i] = o.begin_node[i].id
        o.index2node = {}
        return o.__dict__
            