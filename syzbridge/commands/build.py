import os, stat

from commands import Command
from subprocess import call

class BuildCommand(Command):
    def __init__(self):
        super().__init__()
        self.args = None

    def add_arguments(self, parser):
        super().add_arguments(parser)
        parser.add_argument('--all', action='store_true',
                            help='build all components')

    def custom_subparser(self, parser, cmd):
        return parser.add_parser(cmd, help='Build essential components')

    def run(self, args):
        self.args = args
        self.check_kvm()
        self.install_requirments()
    
    def check_kvm(self):
        proj_path = os.path.join(os.getcwd(), "syzbridge")
        check_kvm_path = os.path.join(proj_path, "scripts/check-kvm.sh")
        st = os.stat(check_kvm_path)
        os.chmod(check_kvm_path, st.st_mode | stat.S_IEXEC)
        r = call([check_kvm_path], shell=False)
        if r == 1:
            exit(0)

    def install_requirments(self):
        proj_path = os.path.join(os.getcwd(), "syzbridge")
        requirements_path = os.path.join(proj_path, "scripts/install-requirements.sh")
        st = os.stat(requirements_path)
        os.chmod(requirements_path, st.st_mode | stat.S_IEXEC)
        call([requirements_path], shell=False)