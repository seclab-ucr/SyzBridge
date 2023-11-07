class CriticalModuleNotFinish(Exception):
    def __init__(self, obj, *args: object) -> None:
        message = "{} did not finish correctly".format(obj)
        super().__init__(message)
