import os, json, shutil

from commands import Command
from subprocess import call
from infra.tool_box import STREAM_HANDLER, init_logger, request_get, regx_match

class PocCommand(Command):
    FEATURE_LOOP_DEVICE = 1 << 0

    def __init__(self):
        super().__init__()
        self.path_package = os.getcwd() + '/syzmorph'
        self.logger = init_logger(__name__, handler_type=STREAM_HANDLER)

    def add_arguments(self, parser):
        super().add_arguments(parser)
        parser.add_argument('--build',  nargs='?', action='store',
                            help='[string] Build PoC from a results.json file')
        parser.add_argument('--output', '-o',  nargs='?', action='store',
                            help='[string] Write the PoC to the specified path')

    def custom_subparser(self, parser, cmd):
        return parser.add_parser(cmd, help='Build PoC')
    
    def run(self, args):
        self.args = args
        if self.args.build == None:
            print("Missing results.json file")
        if self.args.output == None:
            print("Missing output path")

        if not os.path.exists(self.args.build):
            print("Can not find {}".format(self.args.build))
        if not os.path.exists(self.args.output):
            print("Path {} doesn't exist".format(self.args.output))
        
        results = json.load(open(self.args.build, 'r'))
        if not results['trigger']:
            print("Bug cannot be triggered")
            return
        self.build_poc(results)
    
    def build_poc(self, re):
        extra_cmd = ""
        poc_script = """
#!/bin/bash

set -ex

function solve_feature() {{
    FEATURE=$1
    # FEATURE_LOOP_DEVICE
    if [[ $((FEATURE&1)) == 1 ]]; then
        echo "FEATURE_LOOP_DEVICE"
        # check if loop device is created
        DEV_LIST=`losetup -a | awk '{{{{print $1}}}}'`
        echo "Busy loop devices:\\n" $DEV_LIST

        echo $DEV_LIST |
        while read -r line; do \\
            DEV_NAME=${{line//:/ }}; \\
            echo "free loop device $DEV_NAME"; \\
            umount $DEV_NAME > /dev/null 2>&1 || true; \\
        done
    fi
}}

echo 140800 >  /sys/kernel/debug/tracing/buffer_size_kb
{0}
chmod +x ./poc
while :
do
    nohup ./poc > nohup.out 2>&1 &
    sleep 1
done
"""
        from syzmorph.modules.syzbot import Crawler

        crawler = Crawler()

        crawler.run_one_case(re['hash'])
        case = crawler.cases[re['hash']]
        r = request_get(case['c_repro'])
        c_prog_text = r.text
        print("generating poc.c")
        feature = self.tune_poc(re, c_prog_text)
        if feature != 0:
            extra_cmd += "solve_feature {} || true\n".format(feature)
        if len(re['missing_module']) > 0:
            cmd = []
            for each in re['missing_module']:
                cmd.append("modprobe {}".format(each))
            extra_cmd += " && ".join(cmd) + '\n'
        poc_script = poc_script.format(extra_cmd)
        print("generating /run_poc.sh")

        f = open(self.args.output+'/run_poc.sh', 'w')
        f.writelines(poc_script)
        f.close()
    
    def tune_poc(self, re, text):
        root = re['root']
        feature = 0
        insert_line = []
        main_func = ""

        data = []
        code = text.split('\n')
        if text.find("int main") != -1:
            main_func = r"^int main"

        for i in range(0, len(code)):
            line = code[i].strip()
            if insert_line != []:
                for t in insert_line:
                    if i == t[0]:
                        data.append(t[1])
                        insert_line.remove(t)
            data.append(code[i])
            if re['namespace']:
                if regx_match(main_func, line):
                    data.insert(len(data)-1, "#include \"sandbox.h\"")
                    insert_line.append([i+2, "setup_sandbox();"])

            for each in re['skip_funcs']:
                if regx_match(each, line):
                    data.pop()
                    re['skip_funcs'].remove(each)

            # We dont have too much devices to connect, limit the number to 1
            if '*hash = \'0\' + (char)(a1 % 10);' in line:
                data.pop()
                data.append('*hash = \'0\' + (char)(a1 % 2);')
                re['interface_tuning'].remove('usb')

            if 'setup_loop_device' in line:
                if not (feature & self.FEATURE_LOOP_DEVICE):
                    feature |= self.FEATURE_LOOP_DEVICE
                    re['device_tuning'].remove('loop')

        f = open(self.args.output+'/poc.c', 'w')
        if data != []:
            f.writelines("\n".join(data))
            f.close()
            if re['namespace']:
                src = os.path.join(self.path_package, "plugins/bug_reproduce/sandbox.h")
                dst = os.path.join(self.args.output, "sandbox.h")
                shutil.copyfile(src, dst)
        else:
            self.logger.error("Cannot find real PoC function")
        self._compile_poc(root)
        if self.check_results(re):
            self.logger.error("PoC didn't follow the results.json")
        return feature
    
    def check_results(self, re):
        if len(re['skip_funcs']) != 0:
            self.logger.error("PoC building error: function {} cannot be found".format(re['skip_funcs']))
            return True
        if len(re['interface_tuning']) != 0:
            self.logger.error("PoC building error: interface {} cannot be found".format(re['interface_tuning']))
            return True
        if len(re['device_tuning']) != 0:
            self.logger.error("PoC building error: device {} cannot be found".format(re['device_tuning']))
            return True
        return False
    
    def _compile_poc(self, root: bool):
        poc_file = 'poc.c'
        call(["gcc", "-pthread", "-static", "-o", "poc", poc_file], cwd=self.args.output)