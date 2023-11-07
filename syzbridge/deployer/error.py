class NoValidReproducer(Exception):
    def __init__(self, type, *args: object) -> None:
        super().__init__(*args)
        self.type = type + " reproducer"
        self.message = "Can not find valid "+self.type

class PluginRuntimeError(Exception):
    def __init__(self, message, *args: object) -> None:
        super().__init__(message)