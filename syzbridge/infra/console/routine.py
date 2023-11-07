class Routine:
    def __init__(self, index, hash_val, style):
        self.index = index
        self.hash_val = hash_val
        self.style = style
        self._modules = {}

    def module(self, name):
        if name not in self._modules:
            return None
        return self._modules[name]

    def setup_module(self, name, stage_text, stage_status, style):
        text = stage_text + ' ' + stage_status
        if name not in self._modules:
            self._modules[name] = {'style': style, 'name': name, 'text': text}