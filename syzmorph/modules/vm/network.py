import threading, queue, time

from infra.tool_box import init_logger, set_timer
from subprocess import Popen, PIPE, STDOUT

class Network:
    def __init__(self, logger=None, debug=False, propagate=False):
        self.debug = debug
        self.pipe_output = []
        if logger == None and self.logger == None:
            self.logger = init_logger(logger_id="network", debug=self.debug, propagate=propagate)
    
    def scp(self, ip, user, port, key, src, dst, upload, wait):
        ret_queue = queue.Queue()
        x = threading.Thread(target=self._scp, args=(ip, user, port, key, src, dst, upload, ret_queue), name="scp logger")
        x.start()
        if wait:
            x.join()
            try:
                exitcode = ret_queue.get(block=False)
            except BrokenPipeError:
                return None
            return exitcode
        return None
    
    def ssh(self, ip, user, port, key, command, wait, timeout):
        ret_queue = queue.Queue()
        x = threading.Thread(target=self._ssh, args=(ip, user, port, key, command, ret_queue, timeout), name="ssh logger")
        x.start()
        if wait:
            x.join()
            try:
                pipe_output = ret_queue.get(block=False)
            except BrokenPipeError:
                return None
            return pipe_output
        return None

    def _scp(self, ip, user, port, key, src, dst, upload, ret_queue):
        if upload:
            cmd = ["scp", "-F", "/dev/null", "-o", "UserKnownHostsFile=/dev/null", \
                "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=no", \
                "-i", key, "-P", str(port)]
            cmd.extend(src)
            cmd.append("{}@{}:{}".format(user, ip, dst))
        else:
            cmd = ["scp", "-F", "/dev/null", "-o", "UserKnownHostsFile=/dev/null", \
                "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=no", \
                "-i", key, "-P", str(port)]
            for each in src:
                cmd.append("{}@{}:{}".format(user, ip, each))
            cmd.append(dst)
        
        self.logger.debug(" ".join(cmd))
        p = Popen(cmd,
        stdout=PIPE,
        stderr=STDOUT)
        with p.stdout:
            if self.logger != None:
                self.log_anything(p.stdout, self.logger, self.debug)
        exitcode = p.wait()
        ret_queue.put(exitcode, block=False)
        return exitcode
    
    def _ssh(self, ip, user, port, key, command, ret_queue, timeout=3*60):
        cmd = ["ssh", "-F", "/dev/null", "-o", "UserKnownHostsFile=/dev/null", 
        "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=no", 
        "-i", key, 
        "-p", str(port), "{}@{}".format(user, ip), command]
        pipe_output = []

        self.logger.debug(" ".join(cmd))
        p = Popen(cmd,
        stdout=PIPE,
        stderr=STDOUT)
        if timeout != None:
            x = threading.Thread(target=set_timer, args=(timeout, p, ), name="ssh timer")
            x.start()
        start = len(self.pipe_output)
        with p.stdout:
            if self.logger != None:
                self.log_anything(p.stdout, self.logger, self.debug)
        exitcode = p.wait()
        ret_queue.put(self.pipe_output[start:], block=False)
        return exitcode
    
    def log_anything(self, pipe, logger, debug):
        try:
            for line in iter(pipe.readline, b''):
                try:
                    line = line.decode("utf-8").strip('\n').strip('\r')
                except:
                    logger.info('bytes array \'{}\' cannot be converted to utf-8'.format(line))
                    continue
                logger.info(line)
                self.pipe_output.append(line)
                if debug:
                    print(line)
        except ValueError:
            if pipe.close:
                return