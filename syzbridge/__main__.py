import argparse
import os, sys
import importlib

commands_list = {}
sys.path.append(os.getcwd())
def create_parser():
    parser = argparse.ArgumentParser()
    subparser = parser.add_subparsers(dest='cmd', help='sub-command help')

    proj_dir = os.path.join(os.getcwd(), "syzbridge")
    command_dir = os.path.join(proj_dir, "commands")
    commands = [ cmd[:-3] for cmd in os.listdir(command_dir)
                    if cmd.endswith('.py') and not cmd == '__init__.py']
    for cmd in commands:
        class_name = "{}{}Command".format(cmd[0].upper(), cmd[1:])
        module = importlib.import_module("commands.{}".format(cmd))
        new_class = getattr(module, class_name)
        A = new_class()
        parser_cmd = A.custom_subparser(subparser, cmd)
        A.add_arguments(parser_cmd)
        commands_list[cmd] = A
        #parser_cmd.add_argument('--config',  action='store_true', help='test config module')
        #parser.parse_args(['run -h'])
    
    return parser

if __name__ == '__main__':
    parser = create_parser()
    args = parser.parse_args()
    if args.cmd in commands_list:
        commands_list[args.cmd].run(args)
    else:
        parser.print_help()
    exit(0)