class ParseConfigError(Exception):
    def __init__(self, key, *args: object) -> None:
        message = "ilegal key \'{}\' in config".format(key)
        super().__init__(message)

class TargetFileNotExist(Exception):
    def __init__(self, file, *args: object) -> None:
        message = "Can not find {}".format(file)
        super().__init__(message)

class TargetFormatNotMatch(Exception):
    def __init__(self, field, type_wrong, type_cor, *args: object) -> None:
        message = "{} should be {}, instead it is {}".format(field, type_cor, type_wrong)
        super().__init__(message)

class KernelTypeError(Exception):
    def __init__(self, type_wrong, *args: object) -> None:
        message = "Kernel type must be either \"upstream\" or \"distro\", instead it is ".format(type_wrong)
        super().__init__(message)

class DuplicatedDistro(Exception):
    def __init__(self, name, *args: object) -> None:
        message = "Already have a distro named {}. If they are different version, please use different name.".format(name)
        super().__init__(message)
