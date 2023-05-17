class CreateSnapshotError(Exception):
    pass

class KASANDoesNotEnabled(Exception):
    def __init__(self, hash_val, *args: object) -> None:
        message = "KASAN is disabled within case {}".format(hash_val)
        super().__init__(message)