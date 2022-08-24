from rich.layout import Layout

class BuildLayout:
    def __init__(self, cases: list):
        self.cases = cases
        self.layout = Layout()
        self._init_layout(len(cases))
    
    def _init_layout(self, n):
        self.layout = Layout()
        self.layout.split(
            Layout(name="Monitor", size=1),
            Layout(name="upper"),
            Layout(name="lower")
        )
        if n > 8:
            # Unsupported
            return

        if n == 8:
            self.layout["upper"].split_row(Layout(name="Proc 0"), Layout(name="Proc 1"), 
                Layout(name="Proc 2"), Layout(name="Proc 3"))
            self.layout["lower"].split_row(Layout(name="Proc 4"), Layout(name="Proc 5"), 
                Layout(name="Proc 6"), Layout(name="Proc 7"))
        self.layout.add_layout(self.table)