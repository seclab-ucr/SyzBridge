from .launcher import Launcher

class Reproducer(Launcher):
    def __init__(self, **kargs):
        Launcher.__init__(self, **kargs)