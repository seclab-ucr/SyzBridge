class ConsoleMessage:
    ERROR = 0
    INFO = 1
    PLUGINS_ORDER = 2

    def __init__(self, hash_val, index):
        self.type = None
        self.message = None
        self.hash_val = hash_val
        self.proc_index = index
        self.module = {}