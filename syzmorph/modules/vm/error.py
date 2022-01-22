class QemuIsDead(Exception):
    pass
class AngrRefuseToLoadKernel(Exception):
    pass

class AlternativeFunctionError(Exception):
    def __init__(self, message, *args: object) -> None:
        super().__init__(message)

class KasanReportEntryNotFound(Exception):
    pass