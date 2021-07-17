import threading

from serena.infra.tool_box import *
from subprocess import Popen, PIPE, STDOUT

class Network:
    def __init__(self, logger=None, debug=False, propagate=False):
        self.debug = debug
        if logger == None and self.logger == None:
            self.logger = init_logger(logger_id="network", debug=self.debug, propagate=propagate)

    def scp(self, ip, user, port, key, src, dst):
        cmd = ["scp", "-F", "/dev/null", "-o", "UserKnownHostsFile=/dev/null", \
            "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=no", \
            "-i", key, "-P", str(port), src, "{}@{}:{}".format(user, ip, dst)]
        
        p = Popen(cmd,
        stdout=PIPE,
        stderr=STDOUT)
        with p.stdout:
            if self.logger != None:
                log_anything(p.stdout, self.logger, self.debug)
        exitcode = p.wait()
        return exitcode
    
    def ssh(self, ip, user, port, key, command):
        cmd = ["ssh", "-F", "/dev/null", "-o", "UserKnownHostsFile=/dev/null", 
        "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=no", 
        "-i", key, 
        "-p", str(port), "{}@{}".format(user, ip), command]

        p = Popen(cmd,
        stdout=PIPE,
        stderr=STDOUT)
        with p.stdout:
            if self.logger != None:
                x = threading.Thread(target=log_anything, args=(p.stdout, self.logger, self.debug,), name="ssh logger")
                x.start()
        return 0