class Command():
    def __init__(self):
        pass

    def add_arguments(self, parser):
        parser.add_argument('--debug',  action='store_true', help='debug module')
    
    def custom_subparser(self, parser, cmd):
        return None

    def run(self):
        pass