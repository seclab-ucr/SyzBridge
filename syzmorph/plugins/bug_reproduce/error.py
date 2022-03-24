class KASANDoesNotEnabled(Exception):
    def __init__(self, obj, *args: object) -> None:
        message = "KASAN is disabled, stopping all instances, make sure enable KASAN in kernel config"
        super().__init__(message)