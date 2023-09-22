class KASANDoesNotEnabled(Exception):
    def __init__(self, hash_val, *args: object) -> None:
        message = "KASAN is disabled within case {}".format(hash_val)
        super().__init__(message)
    
class ModprobePaniced(Exception):
    def __init__(self, mod, *args: object) -> None:
        message = "Modprobe paniced when loading {}".format(mod)
        self.mod = mod
        super().__init__(message)

class PlguinUnknownError(Exception):
    def __init__(self, *args: object) -> None:
        message = "Unknown error occurs"
        super().__init__(message)