from ..tool_box import regx_getall
from .error import NodeScopeError, NodeTextError

class Node:
    def __init__(self, line):
        self.children = []
        self.parent = None
        self.depth = 0
        self.is_leaf = False
        self.is_root = False
        self.is_function = False
        self.is_function_exit = False
        self.is_function_entry = False
        self.prefix = '|'
        self.scope_begin_node = None
        self.scope_end_node = None
        self.next_sibling = None
        self.next_node = None
        self.function_name = None

        self.index = 0
        self.cpu = None
        self.time_stamp = None
        self.task = None
        self.pid = None
        self.latency = None
        self.event = None
        self.info = None
        self.parse(line)

    def parse(self, line):
        ftrace_line_regx = r'(<\.\.\.>|[a-zA-Z0-9\-\_\.]+)-(\d+)( )+\[(\d+)\]( )+(\d+\.\d+): (funcgraph_entry|funcgraph_exit):.+(\|( )+)(([A-Za-z0-9_.]+\(\))(;|)|})'

        self.line = line
        try:
            m = regx_getall(ftrace_line_regx, self.line)[0]
        except IndexError:
            raise NodeTextError(self.line)
        self.task = m[0]
        self.pid = int(m[1])
        self.cpu = int(m[3])
        self.time_stamp = m[5]
        self.event = m[6]
        self.info = m[9]

        if m[9] == '}':
            self.is_function = False
            self.is_leaf = True
            self.is_root = False
        else:
            self.is_function = True
            self.function_name = m[10][:-2]
            if m[11] == ';':
                self.is_leaf = True
                self.is_root = False
            elif self.is_function:
                self.is_root = True
                self.is_leaf = False
        
        if self.is_root:
            self.scope_begin_node = self
        
        if self.event == 'funcgraph_entry':
            self.is_function_entry = True
        if self.event == 'funcgraph_exit' or self.is_leaf:
            self.is_function_exit = True

    def add_node(self, node):
        if not isinstance(node, Node):
            raise TypeError('child must be of type Node')
        
        self.next_node = node
        node.index = self.index + 1
        if node.is_function:
            if self.is_root:
                self.add_child(node)
            if self.is_leaf:
                self.add_siblings(node)
        if not node.is_function:
            self.scope_end(node, self.is_function_exit)
        if node.parent == None and node.depth > 0:
            raise NodeScopeError(node.line)
    
    def add_child(self, child):
        if not isinstance(child, Node):
            raise TypeError('child must be of type Node')
        
        self.children.append(child)
        child.prefix = self.prefix + ' |'
        child.parent = self
        child.depth = self.depth + 1
        if child.is_root:
            self.scope_begin(child)
    
    def add_siblings(self, node):
        if not isinstance(node, Node):
            raise TypeError('child must be of type Node')
        
        self.next_sibling = node
        if self.parent != None:
            self.parent.add_child(node)

    
    def scope_begin(self, node):
        if not isinstance(node, Node):
            raise TypeError('child must be of type Node')
        
        pass

    def scope_end(self, node, previous_function_exit):
        if not isinstance(node, Node):
            raise TypeError('child must be of type Node')
        if previous_function_exit:
            self.parent.scope_end_node = node
            node.scope_end_node = node
            node.scope_begin_node = self.parent
            node.depth = node.scope_begin_node.depth
            node.parent = node.scope_begin_node.parent
            node.prefix = node.scope_begin_node.prefix
        else:
            self.scope_end_node = node
            node.scope_end_node = node
            node.scope_begin_node = self
            node.depth = node.scope_begin_node.depth
            node.parent = node.scope_begin_node.parent
            node.prefix = node.scope_begin_node.prefix
    
    @property
    def text(self):
        header = "{} | {} | [{}] | {}: {}:".format(self.task, self.pid, self.cpu, self.time_stamp, self.event)
        align = 70 - len(header)
        return "{}{}{}{}".format(header, align*' ', self.prefix, self.info)
    
    def dump(self):
        node = self
        print(node.text)
        while node.next_node != None:
            node = node.next_node
            print(node.text)
    
    def dump_to_file(self, file_name):
        with open(file_name, 'w') as f:
            node = self
            f.write(node.text + '\n')
            while node.next_node != None:
                node = node.next_node
                f.write(node.text + '\n')
            f.close()
        