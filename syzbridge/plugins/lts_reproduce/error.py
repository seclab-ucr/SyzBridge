class CloneKernelFailed(Exception):
    def __init__(self, kernel, *args: object) -> None:
        message = "Encountered error when cloning {}".format(kernel)
        super().__init__(message)