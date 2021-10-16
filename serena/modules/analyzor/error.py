class CannotFindConfigForObject(Exception):
    def __init__(self, obj, *args: object) -> None:
        message = "Can not find config for "+obj
        super().__init__(message)

class AnalysisModuleError(Exception):
    pass

class CannotFindKernelConfig(Exception):
    def __init__(self, *args: object) -> None:
        message = "Can not find \"debian/build/build-generic/.config\""
        super().__init__(message)