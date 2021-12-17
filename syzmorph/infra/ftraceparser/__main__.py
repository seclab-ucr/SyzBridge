import sys, os
sys.path.append(os.getcwd())

import argparse
import terminal
import trace_cmd
def parse_args():
    parser = argparse.ArgumentParser(description='Ftrace Parser')
    parser.add_argument('file', nargs='?', type=str, help='Ftrace file')
    parser.add_argument('-i', nargs='?', type=str, help='Process to run')
    return parser.parse_args()

if __name__ == '__main__':
    args = parse_args()
    if args.i != None:
        tc = trace_cmd.TraceCmd(args.i)
        cmd = tc.get_record_cmd()
        if cmd != None:
            print(cmd)
        exit(0)
    t = terminal.Terminal(args.file)
    t.run()