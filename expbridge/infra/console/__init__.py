from .interface import Interface

class CoolConsole(Interface):
    def __init__(self, title, pm, queue):
        Interface.__init__(self, title, pm, queue)

    