class ParseConfigError(Exception):
    def __init__(self, key, *args: object) -> None:
        message = "ilegal key \'{}\' in config".format(key)
        super().__init__(message)

class TargetFileNotExist(ParseConfigError):
    def __init__(self, file, *args: object) -> None:
        message = "Can not find {}".format(file)
        super().__init__(message)

class TargetFormatNotMatch(ParseConfigError):
    def __init__(self, field, type_wrong, type_cor, *args: object) -> None:
        message = "{} should be {}, but instead it is {}".format(field, type_cor, type_wrong)
        super().__init__(message)