import threading

from serena.infra.tool_box import *
from subprocess import Popen, PIPE, STDOUT

class Network:
    def __init__(self, logger=None, debug=False, propagate=False):
        self.debug = debug
        if logger == None and self.logger == None:
            self.logger = init_logger(logger_id="network", debug=self.debug, propagate=propagate)
    
    def scp(self, ip, user, port, key, src, dst, wait):
        x = threading.Thread(target=self._scp, args=(ip, user, port, key, src, dst,), name="scp logger")
        x.start()
        if wait:
            x.join()
    
    def ssh(self, ip, user, port, key, command, wait):
        x = threading.Thread(target=self._ssh, args=(ip, user, port, key, command,), name="ssh logger")
        x.start()
        if wait:
            x.join()

    def _scp(self, ip, user, port, key, src, dst):
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
    
    def _ssh(self, ip, user, port, key, command):
        cmd = ["ssh", "-F", "/dev/null", "-o", "UserKnownHostsFile=/dev/null", 
        "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=no", 
        "-i", key, 
        "-p", str(port), "{}@{}".format(user, ip), command]

        p = Popen(cmd,
        stdout=PIPE,
        stderr=STDOUT)
        with p.stdout:
            if self.logger != None:
                log_anything(p.stdout, self.logger, self.debug)
        exitcode = p.wait()
        return exitcode