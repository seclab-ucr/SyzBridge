class CannotFindConfigForObject(Exception):
    def __init__(self, obj, *args: object) -> None:
        super().__init__(*args)
        self.obj = obj
        self.message = "Can not find config for "+self.obj

class AnalysisModuleError(Exception):
    pass