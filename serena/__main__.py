import argparse
import multiprocessing, threading
import os, stat, sys
import json, gc

sys.path.append(os.getcwd())
from queue import Empty
from subprocess import call
from serena.modules.syzbot import Crawler
from serena.modules.deployer.deployer import Deployer

def args_parse():
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter,
                description='')
    parser.add_argument('-i', '--input', nargs='?', action='store',
                        help='The input should be a valid hash or a file contains multiple hashs. -u, -m ,and -k will be ignored if -i is enabled.')
    parser.add_argument('-u', '--url', nargs='?', action='store',
                        default="https://syzkaller.appspot.com/upstream",
                        help='Indicate an URL for automatically crawling and running.\n'
                             '(default value is \'https://syzkaller.appspot.com/upstream\')')
    parser.add_argument('-I', '--image', nargs=1, action='store',
                        help='Linux image for bug reproducing')
    parser.add_argument('-v', '--vmlinux', nargs='?', action='store',
                        help='vmlinux for debugging')
    parser.add_argument('-k', '--key', nargs='*', action='store',
                        default=[''],
                        help='The keywords for detecting cases.\n'
                             '(By default, it retrieve all cases)\n'
                             'This argument could be multiple values')
    parser.add_argument('-m', '--max', nargs='?', action='store',
                        default='9999',
                        help='The maximum of cases for retrieving\n'
                             '(By default all the cases will be retrieved)')
    parser.add_argument('--filter-by-reported', nargs='?',
                        default='-1',
                        help='filter bugs by the days they were reported\n')
    parser.add_argument('--filter-by-closed', nargs='?',
                        default='-1',
                        help='filter bugs by the days they were closed\n')
    parser.add_argument('--include-high-risk', action='store_true',
                        help='Include high risk bugs for analysis')
    parser.add_argument('--use-cache',
                        action='store_true',
                        help='Read cases from cache, this will overwrite the --input feild')
    parser.add_argument('-pm', '--parallel-max', nargs='?', action='store',
                        default='1', help='The maximum of parallel processes\n'
                                        '(default valus is 1)')
    parser.add_argument('--ssh', nargs='?', action='store',
                        help='The default port of ssh using by QEMU\n'
                        '(default port is 36777)')
    parser.add_argument('--ssh-key', nargs=1, action='store',
                        help='The private key for ssh connection')
    parser.add_argument('--debug', action='store_true',
                        help='Enable debug mode')
    args = parser.parse_args()
    return args

def check_kvm():
    proj_path = os.path.join(os.getcwd(), "serena")
    check_kvm_path = os.path.join(proj_path, "scripts/check-kvm.sh")
    st = os.stat(check_kvm_path)
    os.chmod(check_kvm_path, st.st_mode | stat.S_IEXEC)
    r = call([check_kvm_path], shell=False)
    if r == 1:
        exit(0)

def install_requirments():
    proj_path = os.path.join(os.getcwd(), "serena")
    requirements_path = os.path.join(proj_path, "scripts/install-requirements.sh")
    st = os.stat(requirements_path)
    os.chmod(requirements_path, st.st_mode | stat.S_IEXEC)
    call([requirements_path], shell=False)

def cache_cases(cases):
    work_path = os.getcwd()
    cases_json_path = os.path.join(work_path, "work/cases.json")
    with open(cases_json_path, 'w') as f:
        json.dump(cases, f)
        f.close()

def read_cases_from_cache():
    cases = {}
    work_path = os.getcwd()
    cases_json_path = os.path.join(work_path, "work/cases.json")
    if os.path.exists(cases_json_path):
        with open(cases_json_path, 'r') as f:
            cases = json.load(f)
            f.close()
    return cases

def deploy_one_case(index, args, hash_val):
    case = crawler.cases[hash_val]
    dp = Deployer(index=index, args=args, action=Deployer.ACTION_BUG_REPRODUCE, case_hash=hash_val, case=case)
    dp.deploy()
    del dp

def prepare_cases(index, args):
    while(1):
        lock.acquire(blocking=True)
        try:
            hash_val = g_cases.get(block=True, timeout=3)
            print("Thread {}: run case {} [{}/{}] left".format(index, hash_val, rest.value-1, total))
            rest.value -= 1
            lock.release()
            x = multiprocessing.Process(target=deploy_one_case, args=(index, args, hash_val,), name="lord-{}".format(i))
            x.start()
            x.join()
            gc.collect()
        except Empty:
            lock.release()
            break
    print("Thread {} exit->".format(index))

if __name__ == '__main__':
    args = args_parse()
    check_kvm()
    install_requirments()

    crawler = Crawler(url=args.url, keyword=args.key, max_retrieve=int(args.max), 
        filter_by_reported=int(args.filter_by_reported), filter_by_closed=int(args.filter_by_closed), 
        include_high_risk=args.include_high_risk, debug=args.debug)
    
    if args.input != None:
        if len(args.input) == 40:
            crawler.run_one_case(args.input)
        else:
            with open(args.input, 'r') as f:
                text = f.readlines()
                for line in text:
                    line = line.strip('\n')
                    crawler.run_one_case(line)
    else:
        if args.use_cache:
            crawler.cases = read_cases_from_cache()
        else:
            crawler.run()
    
    if not args.use_cache:
        cache_cases(crawler.cases) 
    
    manager = multiprocessing.Manager()
    lock = threading.Lock()
    g_cases = manager.Queue()
    for key in crawler.cases:
        g_cases.put(key)
    
    parallel_max = int(args.parallel_max)
    l = list(crawler.cases.keys())
    total = len(l)
    rest = manager.Value('i', total)
    for i in range(0,min(parallel_max,total)):
        x = threading.Thread(target=prepare_cases, args=(i, args,), name="lord-{}".format(i))
        x.start()