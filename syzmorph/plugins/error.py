
class CannotFindConfigForObject(Exception):
    def __init__(self, obj, *args: object) -> None:
        message = "Can not find config for "+obj
        super().__init__(message)

class AnalysisModuleError(Exception):
    def __init__(self, message, *args: object) -> None:
        super().__init__(message)

class CannotFindKernelConfig(Exception):
    def __init__(self, *args: object) -> None:
        message = "Can not find \"config\""
        super().__init__(message)

class PluginFolderReachMaximumNumber(Exception):
    def __init__(self, message, *args: object) -> None:
        super().__init__(message)