from .launcher import Launcher

class Reproducer(Launcher):
    def __init__(self, **kargs):
        super().__init__(**kargs)