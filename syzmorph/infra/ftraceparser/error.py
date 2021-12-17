class NodeScopeError(Exception):
    def __init__(self, line, *args: object) -> None:
        message = "NodeScopeError: node %s is not in scope " % (line)
        super().__init__(message)

class NodeTextError(Exception):
    def __init__(self, line, *args: object) -> None:
        message = "NodeTextError: node %s has invalid format" % (line)
        super().__init__(message)