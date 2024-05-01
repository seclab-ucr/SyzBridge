
class FailToBuildKernel(Exception):
    def __init__(self, hash_val, *args: object) -> None:
        message = "Fail to build kernel for "+hash_val
        super().__init__(message)
