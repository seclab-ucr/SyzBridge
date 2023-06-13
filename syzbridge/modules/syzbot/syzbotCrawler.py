from subprocess import Popen, PIPE, STDOUT
import threading
import requests
import time
import pandas as pd
import re, os, shutil
from syzbridge.infra.config.config import Config
from syzbridge.infra.config.vendor import Vendor
from syzbridge.modules.vm import VM

from syzbridge.infra.tool_box import *
from bs4 import BeautifulSoup
from bs4 import element
from datetime import date, timedelta
from .error import *

syzbot_bug_base_url = "bug?id="
syzbot_bug_extid_url = "bug?extid="
syzbot_host_url = "https://syzkaller.appspot.com/"
num_of_elements = 8

class Crawler:
    def __init__(self,
                 url="https://syzkaller.appspot.com/upstream/fixed",
                 keyword=[], max_retrieve=99999, filter_by_reported="", log_path = ".", cfg=None,
                 filter_by_closed="", filter_by_c_prog=False, filter_by_kernel=[], 
                 filter_by_fixes_tag=False, filter_by_patch=False, filter_by_hashs=[],
                 filter_by_distro_cycle_start=False, filter_by_distro_cycle_end=False,
                 match_single_distro=False, filter_by_syz_prog=False,
                 include_high_risk=True, debug=False):
        self.url = url
        if type(keyword) == list:
            self.keyword = keyword
        else:
            print("keyword must be a list")
        self.max_retrieve = max_retrieve
        self.cases = {}
        self._patches = {}
        self._patch_info = {}
        self.include_high_risk = include_high_risk
        self._log_path = log_path
        self._debug = debug
        self.logger = init_logger(log_path + "/syzbot.log", debug = debug, propagate=True)
        self.filter_by_reported = [-1, -1]
        self.filter_by_closed = [-1, -1]
        self.filter_by_distro_cycle_start = filter_by_distro_cycle_start
        self.filter_by_distro_cycle_end = filter_by_distro_cycle_end or match_single_distro
        self.filter_by_distro_effective_cycle = filter_by_distro_cycle_start or filter_by_distro_cycle_end
        self.distro_vm = {}
        self.match_single_distro = match_single_distro
        if filter_by_reported != "":
            n = filter_by_reported.split('-')
            n[0] = int(n[0])
            n[1] = int(n[1])
            if n[0] > n[1]:
                self.filter_by_reported[0] = n[1]
                self.filter_by_reported[1] = n[0]
            else:
                self.filter_by_reported[0] = n[0]
                self.filter_by_reported[1] = n[1]
        if filter_by_closed != "":
            n = filter_by_closed.split('-')
            n[0] = int(n[0])
            n[1] = int(n[1])
            if n[0] > n[1]:
                self.filter_by_closed[0] = n[1]
                self.filter_by_closed[1] = n[0]
            else:
                self.filter_by_closed[0] = n[0]
                self.filter_by_closed[1] = n[1]
        self.filter_by_syz_prog= filter_by_syz_prog
        self.filter_by_c_prog = filter_by_c_prog
        self.filter_by_fixes_tag = filter_by_fixes_tag
        self.filter_by_patch = filter_by_patch
        self.filter_by_kernel = filter_by_kernel
        self.filter_by_hashs = filter_by_hashs
        self._fixes = {}
        if cfg != None:
            self.cfg: Config = cfg
        else:
            self.cfg = None
        self.thread_lock = None
        if self.filter_by_fixes_tag or self.filter_by_patch:
            self.logger.info("Wait for distro VMs are ready")
            if not self.wait_for_distro_vm_ready():
                self.distro_vm_kill()
                return

    def __del__(self):
        if self.filter_by_fixes_tag or self.filter_by_patch:
            self.distro_vm_kill()

    def run(self):
        cases_hash, high_risk_impacts = self.gather_cases()
        for each in cases_hash:
            self._patch_info = {'url': None, 'fixes':[]}
            if each['Hash'] in self.filter_by_hashs:
                self.logger.debug("Skip {} because it's filtered by hash_val match".format(each['Hash']))
                continue
            patch_url = None
            if 'Patch' in each:
                patch_url = each['Patch']
                if patch_url in self._patches or \
                    (patch_url in high_risk_impacts and not self.include_high_risk):
                    continue
                self._patches[patch_url] = True
            self._patch_info['url'] = patch_url
            if self.filter_by_fixes_tag or self.filter_by_patch:
                if patch_url == None or not self.check_excluded_distro(each['Hash'], patch_url):
                    if patch_url == None:
                        self.logger.debug("{} does not have a patch url".format(each['Hash']))
                    else:
                        self.logger.debug("{} does not have a fixes tag".format(each['Hash']))
                    if each['Hash'] in self.cases:
                        self.cases.pop(each['Hash'])
                    continue
            if self.retreive_case(each['Hash']) != -1:
                if self.filter_by_distro_effective_cycle:
                    self.cases[each['Hash']]['affect'] = self.get_affect_distro(int(each['Reported']))
                    if len(self.cases[each['Hash']]['affect']) == 0:
                        self.logger.debug("{} does not affect any distro within its life cycle".format(each['Hash']))
                        self.cases.pop(each['Hash'])
                        continue
                else:
                    self.cases[each['Hash']]['affect'] = None
                self.cases[each['Hash']]['title'] = each['Title']
                self.cases[each['Hash']]['patch'] = self._patch_info
        return
    
    def wait_for_distro_vm_ready(self):
        for distro in self.cfg.get_all_distros():
            if 'ubuntu' not in distro.distro_name.lower():
                continue
            new_image = self.create_snapshot(distro.distro_image, self._log_path, distro.distro_name)
            vm = VM(linux=None, kernel=distro, hash_tag="syzbot {}".format(distro.distro_name), work_path=self._log_path, 
                log_name='syzbot-{}.log'.format(distro.distro_name), logger=None,
                port=distro.ssh_port, key=distro.ssh_key, image=new_image, mem="4G", cpu='2')
            vm.run()
            self.distro_vm[distro.distro_name] = vm
        
        for distro_name in self.distro_vm:
            while not self.distro_vm[distro_name].qemu_ready:
                if self.distro_vm[distro_name].instance.poll() != None:
                    self.logger.error("VM {} exit abnormally".format(distro_name))
                    return False
                time.sleep(3)
        return True

    def distro_vm_kill(self):
        for distro_name in self.distro_vm:
            self.distro_vm[distro_name].destroy()
    
    def create_snapshot(self, src, img, image_name):
        dst = "{}/{}-snapshot.img".format(img, image_name)
        self.logger.debug("Create image {} from {}".format(dst, src))
        if os.path.isfile(dst):
            os.remove(dst)
        cmd = ["qemu-img", "create", "-f", "qcow2", "-b", src, dst]
        p = Popen(cmd, stderr=STDOUT, stdout=PIPE)
        p.wait()
        return dst

    def ubuntu_is_vulnerable(self, distro: Vendor, fixes_commit_msg, patch_commit_msg):
        vm = self.distro_vm[distro.distro_name]
        os.path.basename(distro.distro_src)

        # Fedora has different kernel folder name, use * to match it
        kernel_folder = "~/{}/*kernel".format(os.path.basename(distro.distro_src))

        if self.filter_by_fixes_tag:
            blame_commits = self._get_commit_from_msg(distro, vm, kernel_folder, fixes_commit_msg)
            self.logger.debug("{}: Buggy commit blames to commits: {}".format(distro.distro_name, blame_commits))
            for hash_val in blame_commits:
                ret = self._commit_is_ancestor(distro, vm, kernel_folder, hash_val, 'HEAD')
                self.logger.debug("Commit {} is ancestor of HEAD: {}".format(hash_val, ret))
                if not ret:
                    self.logger.debug('{}: Buggy commit does not exist'.format(distro.distro_name))
                    return False
            
            if len(blame_commits) == 0:
                return False

        if self.filter_by_patch:
            blame_commits = self._get_commit_from_msg(distro, vm, kernel_folder, patch_commit_msg)
            self.logger.debug("{}: Patch commit blames to commits: {}".format(distro.distro_name, blame_commits))
            for hash_val in blame_commits:
                ret = self._commit_is_ancestor(distro, vm, kernel_folder, hash_val, 'HEAD')
                self.logger.debug("{}: Commit {} is ancestor of HEAD: {}".format(distro.distro_name, hash_val, ret))
                if ret:
                    self.logger.debug('{}: Patch commit exists in'.format(distro.distro_name))
                    return False
            
        self.logger.debug('{} is vulnerable'.format(distro.distro_name))
        return True
    """
    def fedora_is_vulnerable(self, distro: Vendor, vul_version, patched_version):
        if self.filter_by_fixes_tag:
            self.logger.debug("Compare buggy version {} and distro version {}".format(vul_version, distro.distro_version))
            if not self.is_newer_version(vul_version, distro.distro_version):
                return False
        
        if self.filter_by_patch:
            self.logger.debug("Compare patched version {} and distro version {}".format(patched_version, distro.distro_version))
            if self.is_newer_version(patched_version, distro.distro_version):
                if distro.distro_name not in self._fixes['exclude']:
                    return False
        return True
    """

    def debian_fedora_is_vulnerable(self, distro: Vendor, fixes_commit_msg, patch_commit_msg):
        repo_path = os.getcwd()+"/tools/linux-stable-0"
        cur_commit = None
        self.thread_lock.acquire()
        if not os.path.exists(repo_path):
            ret = clone_repo("https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git", repo_path)
            if ret != 0:
                self.thread_lock.release()
                return None
        self.thread_lock.release()
        
        in_branch = False
        major_version = regx_get(r'^(\d+\.\d+)', distro.distro_version, 0)
        
        out = local_command(command="git log origin/linux-{}.y --oneline --grep \"Linux {}\" -1 | awk '{{print $1}}'".format(major_version, distro.distro_version),
                            cwd=repo_path, shell=True)
        for line in out:
            line = line.strip()
            if line != "":
                cur_commit = line
        if cur_commit == None:
            self.logger.error("Fail to get current commit for {}".format(distro.distro_version))
            return False

        self.logger.debug("{}: current commit is {}".format(distro.distro_name, cur_commit))
        
        if self.filter_by_fixes_tag:
            blame_fixes_commits = self._get_commit_from_msg(distro, None, repo_path, fixes_commit_msg, "origin/linux-{}.y".format(major_version))
            if len(blame_fixes_commits) == 0:
                return False
        
        if self.filter_by_patch:
            blame_patch_commits = self._get_commit_from_msg(distro, None, repo_path, patch_commit_msg, "origin/linux-{}.y".format(major_version))
        
        self.thread_lock.acquire()
        out = local_command(command="git stash -u && git checkout origin/linux-{}.y".format(major_version), cwd=repo_path, shell=True, redir_err=False)
        for line in out:
            if regx_match(r'HEAD is now at [a-z0-9]+ Linux {}\.\d+'.format(major_version), line):
                self.logger.debug(line)
                in_branch = True
                break
        if not in_branch:
            self.logger.error("Fail to checkout branch linux-{}.y".format(major_version))
            self.thread_lock.release()
            return False
        
        if self.filter_by_fixes_tag:
            for hash_val in blame_fixes_commits:
                ret = self._commit_is_ancestor(distro, None, repo_path, hash_val, cur_commit)
                self.logger.debug("{}: Commit {} is ancestor of {}: {}".format(distro.distro_name, hash_val, cur_commit, ret))
                if not ret:
                    self.logger.debug('{}: Buggy commit exists'.format(distro.distro_name))
                    self.thread_lock.release()
                    return False
            
            self.logger.debug("{}: fixes tag is ancestor of current commit".format(distro.distro_name))
        
        if self.filter_by_patch:
            for hash_val in blame_patch_commits:
                ret = self._commit_is_ancestor(distro, None, repo_path, hash_val, cur_commit)
                self.logger.debug("{}: Commit {} is ancestor of {}: {}".format(distro.distro_name, hash_val, cur_commit, ret))
                if ret:
                    self.logger.debug('{}: Patch commit exists'.format(distro.distro_name))
                    self.thread_lock.release()
                    return False
            self.logger.debug("{}: patch is not ancestor of current commit".format(distro.distro_name))
        self.thread_lock.release()
        
        self.logger.debug('{} is vulnerable'.format(distro.distro_name))
        return True
    
    def _commit_is_ancestor(self, distro: Vendor, vm, kernel_folder, ancestor_commit, cur_commit):
        if vm != None:
            out = vm.command(user=distro.root_user, 
                cmds="cd {} && git merge-base --is-ancestor {} {}; echo $?".format(kernel_folder, ancestor_commit, cur_commit), 
                wait=True)
        else:
            out = local_command(command="cd {} && git merge-base --is-ancestor {} {}; echo $?".format(kernel_folder, ancestor_commit, cur_commit), shell=True)
        for line in out:
            line = line.strip()
            if line == "0":
                return True
        return False
    
    def _get_commit_from_msg(self, distro: Vendor, vm: VM, kernel_folder, msg, branch=None):
        res = []
        if branch == None:
            cmds = "cd {} && git log --pretty=format:\"%H %s\" --grep \"^{}$\" -1 | awk '{{print $1}}'".format(kernel_folder, msg)
        else:
            cmds = "cd {} && git log {} --pretty=format:\"%H %s\" --grep \"^{}$\" -1 | awk '{{print $1}}'".format(kernel_folder, branch, msg)
        if vm != None:
            out = vm.command(user=distro.root_user, 
                cmds=cmds, 
                wait=True)
        else:
            out = local_command(command=cmds, shell=True)
        for line in out:
            line = line.strip()
            if len(line) == 40:
                res.append(line)
        return res

    def get_linux_commit_msg(self, commit, soup):
        m = self.get_linux_commit_date_offline(commit, soup)
        return m

    def get_patch_url(self, hash_val):
        url = self._get_case_url(hash_val)
        req = request_get(url)
        soup = BeautifulSoup(req.text, "html.parser")
        try:
            fix = soup.find('span', {'class': 'mono'})
            #fix = soup.body.span.contents[1]
            url = fix.contents[1].attrs['href']
            res=url
        except:
            res=None
        return res
    
    def distro_affect_by_time(self, date_diff):
        res = []
        if self.cfg == None or date_diff == None:
            return None
        today = date.today()
        report_date = today-timedelta(days=date_diff)
        self.logger.debug("bug was reported {} days ago ({})".format(date_diff, report_date))
        closest_date = None
        for distro in self.cfg.get_all_distros():
            if self.filter_by_distro_cycle_end:
                if distro.effective_cycle_end != "":
                    effective_end_date_diff = today - pd.to_datetime(distro.effective_cycle_end).date()
                    if date_diff <= effective_end_date_diff.days:
                        continue

            if self.filter_by_distro_cycle_start:
                if distro.effective_cycle_start != "":
                    effective_start_date_diff = today - pd.to_datetime(distro.effective_cycle_start).date()
                    if date_diff > effective_start_date_diff.days:
                        continue
                    if closest_date == None or closest_date > effective_start_date_diff.days:
                        closest_date = effective_start_date_diff.days
                        if len(res) > 0:
                            res = []

            res.append(distro.distro_name)
        return res

    def get_affect_distro(self, reported_date: int):
        res = self.distro_affect_by_time(reported_date)
        self.logger.debug("Bug might affects {}".format(res))
        if res == None:
            return None
        if self.filter_by_fixes_tag:
            for fix in self._patch_info['fixes']:
                self.logger.debug("Exclude {}".format(fix))
                for each in fix['exclude']:
                    if each in res:
                        res.remove(each)
        self.logger.debug("Bug affects {}".format(res))
        return res
    
    def check_excluded_distro(self, hash_val, patch_url):
        req = requests.request(method='GET', url=patch_url)
        soup = BeautifulSoup(req.text, "html.parser")
        self._patch_info['url'] = patch_url
        patch_hash = patch_url.split("id=")[1]
        self.thread_lock = threading.Lock()
        try:
            msg = soup.find('div', {'class': 'commit-msg'}).text
            self._patch_info['fixes'] = []
            for line in msg.split('\n'):
                if line.startswith('Fixes:'):
                    fix_hash = regx_get(r'Fixes: ([a-z0-9]+)', line, 0)
                    self._fixes = {'hash_val': fix_hash, 'exclude': []}
                    self.logger.debug("Fix tag {}".format(fix_hash))

                    # We want to save all fixes tag info
                    # don't return too early
                    if self.cfg == None:
                        continue

                    threads = []
                    for distro in self.cfg.get_all_distros():
                        t = threading.Thread(target=self._check_distro_vulnerable, args=(distro, fix_hash, patch_hash, soup))
                        t.start()
                        threads.append(t)
                    
                    for t in threads:
                        while t.is_alive():
                            time.sleep(3)
                    self._patch_info['fixes'].append(self._fixes)

        except Exception as e:
            self.logger.exception("Error parsing fix tag for {}: {}".format(hash_val, e))
        return self._patch_info['fixes'] != []

    def _check_distro_vulnerable(self, distro: Vendor, fix_hash, patch_hash, soup):
        vul_version = self.closest_tag(fix_hash, soup)
        patched_version = self.closest_tag(patch_hash, soup)
        fixes_commit_msg = self.get_linux_commit_msg(fix_hash, soup)
        patch_commit_msg = self.get_linux_commit_msg(patch_hash, soup)
        self.logger.debug("fixes commit: {}".format(fix_hash))
        self.logger.debug("patch commit: {}".format(patch_hash))
        if fixes_commit_msg == None:
            self.logger.error("Can't get commit msg for {}. ".format(fix_hash))
            return
        if patch_commit_msg == None:
            self.logger.error("Can't get commit msg for {}. ".format(patch_hash))
            return
        if vul_version == None:
            self.logger.error("Can't get vulnerable version for {}. ".format(fix_hash))
            return
        if patched_version == None:
            self.logger.error("Can't get patched version for {}. ".format(patch_hash))
            return
        self.logger.debug("Check distro {}".format(distro.distro_name))
        if 'ubuntu' in distro.distro_name.lower():
            if not self.ubuntu_is_vulnerable(distro, fixes_commit_msg, patch_commit_msg):
                self.logger.debug("{} is not vulnerable to this bug".format(distro.distro_name))
                self._fixes['exclude'].append(distro.distro_name)
        if 'fedora' in distro.distro_name.lower():
            if not self.debian_fedora_is_vulnerable(distro, fixes_commit_msg, patch_commit_msg):
                self.logger.debug("{} is not vulnerable to this bug".format(distro.distro_name))
                self._fixes['exclude'].append(distro.distro_name)
        if 'debian' in distro.distro_name.lower():
            if not self.debian_fedora_is_vulnerable(distro, fixes_commit_msg, patch_commit_msg):
                self.logger.debug("{} is not vulnerable to this bug".format(distro.distro_name))
                self._fixes['exclude'].append(distro.distro_name)

    def closest_tag(self, patch_hash, soup: BeautifulSoup):
        regx_kernel_version = r'^v(\d+\.\d+)'
        repo_path = self._clone_target_repo(soup)
        if repo_path == None:
            return None
        p = Popen(["git describe --contains {}".format(patch_hash)],
            cwd=repo_path,
            shell=True,
            stdout=PIPE, 
            stderr=STDOUT)
        with p.stdout as pipe:
            for line in iter(pipe.readline, b''):
                line = line.strip().decode('utf-8')
                if regx_match(regx_kernel_version, line):
                    base_version = regx_get(regx_kernel_version, line, 0)
                    return base_version
        return None
    
    def is_newer_version(self, old, new):
        o = old.split('.')
        n = new.split('.')
        c = 0
        while True:
            if c >= len(o) or c >= len(n):
                break
            if int(o[c]) < int(n[c]):
                return True
            elif int(o[c]) > int(n[c]):
                return False
            c += 1
        return True
    
    def get_linux_commit_date_offline(self, hash_val, soup: BeautifulSoup):
        repo_path = self._clone_target_repo(soup)
        if repo_path == None:
            return None
        return self.get_linux_commit_info_in_repo(repo_path, hash_val)
    
    def get_linux_commit_info_in_repo(self, repo_path, hash_val):
        p = Popen(["git", "log", hash_val, "--pretty=format:\"%H {->%s<-} %ad\"", "--date=short", "-n", "1"],
            cwd=repo_path,
            stdout=PIPE, 
            stderr=STDOUT)
        with p.stdout as pipe:
            for line in iter(pipe.readline, b''):
                line = line.strip().decode('utf-8')
                m = regx_get(r'[a-z0-9]{40} {->(.*)<-} (\d{4}-\d{2}-\d{2})', line, 0)
                return m
        return None

    def get_linux_commit_date_online(self, hash_val):
        url = "https://github.com/torvalds/linux/search?q={}&type=commits".format(hash_val)
        while True:
            req = requests.request(method='GET', url=url)
            if req.status_code != 429:
                break
            time.sleep(5)
        soup = BeautifulSoup(req.text, "html.parser")
        try:
            search_results = soup.find('div', {'id': 'commit_search_results'}).contents
        except:
            raise NoCommitResults
        for each in search_results:
            if each == '\n':
                continue
            try:
                msg = each.find('a', {'class': 'message markdown-title js-navigation-open'})
                patch_url = msg.attrs['href']
                full_hash_val = regx_get(r'torvalds\/linux\/commit\/([a-z0-9]+)', patch_url, 0)
                if full_hash_val.startswith(hash_val):
                    time_stamp = each.find('relative-time', {'class': 'no-wrap'}).contents[0]
                    return pd.to_datetime(time_stamp)
            except:
                pass
        return None

    def run_one_case(self, hash_val):
        if hash_val in self.filter_by_hashs:
            self.logger.debug("Skip {} because it's filtered by hash_val match".format(hash_val))
            return
        self.logger.info("retreive one case: %s",hash_val)
        patch_url = self.get_patch_url(hash_val)
        if self.retreive_case(hash_val) == -1:
            return
        self._patch_info = {'url': patch_url, 'fixes':[]}
        if self.filter_by_fixes_tag or self.filter_by_patch:
            if patch_url == None or not self.check_excluded_distro(hash_val, patch_url):
                if patch_url == None:
                    self.logger.debug("{} does not have a patch url".format(hash_val))
                else:
                    self.logger.debug("{} does not have a fixes tag".format(hash_val))
                self.cases.pop(hash_val)
                return
        if self.filter_by_distro_effective_cycle:
            report_date = self.case_first_crash(hash_val)
            self.cases[hash_val]['affect'] = self.get_affect_distro(report_date)
            if len(self.cases[hash_val]['affect']) == 0:
                self.logger.error("{} does not affect any distro within its life cycle".format(hash_val))
                self.cases.pop(hash_val)
                return
        else:
            self.cases[hash_val]['affect'] = None
        self.cases[hash_val]['title'] = self.get_title_of_case(hash_val)
        self.cases[hash_val]['patch'] = self._patch_info
        return self.cases[hash_val]
    
    def case_first_crash(self, hash_val):
        url = self._get_case_url(hash_val)
        req = request_get(url)
        soup = BeautifulSoup(req.text, "html.parser")
        date_diff = regx_get(r'First crash: (\d+)d', soup.text, 0)
        if date_diff == None:
            raise None
        return int(date_diff)

    def get_title_of_case(self, hash_val=None, text=None):
        if hash_val==None and text==None:
            self.logger.info("No case given")
            return None
        if hash_val!=None:
            url = self._get_case_url(hash_val)
            req = requests.request(method='GET', url=url)
            soup = BeautifulSoup(req.text, "html.parser")
        else:
            soup = BeautifulSoup(text, "html.parser")
        title = soup.body.b.contents[0]
        return title

    def retreive_case(self, hash_val):
        self.cases[hash_val] = {}
        detail = self.request_detail(hash_val)
        url = self._get_case_url(hash_val)
        if len(detail) < num_of_elements:
            self.logger.error("Failed to get detail of a case {}".format(url))
            self.cases.pop(hash_val)
            return -1
        self.cases[hash_val]["commit"] = detail[0]
        self.cases[hash_val]["syzkaller"] = detail[1]
        self.cases[hash_val]["config"] = detail[2]
        self.cases[hash_val]["syz_repro"] = detail[3]
        self.cases[hash_val]["log"] = detail[4]
        self.cases[hash_val]["c_repro"] = detail[5]
        self.cases[hash_val]["time"] = detail[6]
        self.cases[hash_val]["manager"] = detail[7]
        self.cases[hash_val]["report"] = detail[8]
        self.cases[hash_val]["vul_offset"] = detail[9]
        self.cases[hash_val]["obj_size"] = detail[10]
        self.cases[hash_val]["kernel"] = detail[11]
        self.cases[hash_val]["hash"] = hash_val

    def gather_cases(self):
        high_risk_impacts = {}
        res = []
        tables = self.__get_table(self.url)
        if tables == []:
            self.logger.error("error occur in gather_cases")
            return res, high_risk_impacts
        count = 0
        for table in tables:
            #self.logger.info("table caption {}".format(table.caption.text))
            for case in table.tbody.contents:
                if type(case) == element.Tag:
                    title = case.find('td', {"class": "title"})
                    if title == None:
                        continue
                    if self.keyword == []:
                        crash = self.retrieve_crash(case, title)
                        if crash == None:
                            continue
                        self.logger.debug("[{}] Fetch {}".format(count, crash['Hash']))
                        res.append(crash)
                        count += 1
                    for keyword in self.keyword:
                        keyword = keyword.lower()
                        low_case_title = title.text.lower()
                        if 'out-of-bounds write' in low_case_title or \
                                'use-after-free write' in low_case_title:
                            commit_list = case.find('td', {"class": "commit_list"})
                            try:
                                patch_url = commit_list.contents[1].contents[1].attrs['href']
                            except:
                                continue
                            high_risk_impacts[patch_url] = True
                        if keyword in low_case_title:
                            crash = self.retrieve_crash(case, title)
                            if crash == None:
                                continue
                            self.logger.debug("[{}] Fetch {}".format(count, crash['Hash']))
                            res.append(crash)
                            count += 1
                            break
                    if count == self.max_retrieve:
                        break
        return res, high_risk_impacts
    
    def retrieve_crash(self, case, title):
        crash = {}
        commit_list = case.find('td', {"class": "commit_list"})
        crash['Title'] = title.text
        stats = case.find_all('td', {"class": "stat"})
        crash['Repro'] = stats[0].text
        crash['Bisected'] = stats[1].text
        crash['Count'] = stats[2].text
        crash['Last'] = stats[3].text
        self.logger.debug(title.text)
        try:
            crash['Reported'] = regx_get(r'(\d+)d', stats[3].text, 0)
            if (self.filter_by_reported[1] > -1 and int(crash['Reported']) > self.filter_by_reported[1]) or \
                (self.filter_by_reported[0] > -1 and int(crash['Reported']) < self.filter_by_reported[0]):
                return None
            patch_url = commit_list.contents[1].contents[1].attrs['href']
            crash['Patch'] = patch_url
            crash['Closed'] = regx_get(r'(\d+)d', stats[4].text, 0)
            if (self.filter_by_closed[1] > -1 and int(crash['Closed']) > self.filter_by_closed[1]) or \
                (self.filter_by_closed[0] > -1 and int(crash['Closed']) < self.filter_by_closed[0]):
                return None
        except:
            # patch only works on fixed cases
            pass
        for _ in range(0, 3):
            try:
                ele = title.next
                href = ele.attrs['href']
                break
            except AttributeError:
                title = title.next
        if 'extid' in href:
            hash_val = href[11:]
        else:
            hash_val = href[8:]
        crash['Hash'] = hash_val
        return crash

    def request_detail(self, hash_val, index=1):
        url = self._get_case_url(hash_val)
        self.logger.debug("\nDetail: {}".format(url))
        tables = self.__get_table(url)
        if tables == []:
            print("error occur in request_detail: {}".format(hash_val))
            self.logger.error("[Failed] {} error occur in request_detail".format(url))
            return []
        count = 0
        for table in tables:
            if table.text.find('Crash') != -1:
                for case in table.tbody.contents:
                    if type(case) == element.Tag:
                        targeting_kernel = False
                        kernel = case.find('td', {"class": "kernel"})
                        if self.filter_by_kernel != []:
                            for each in self.filter_by_kernel:
                                if (kernel.text == each):
                                    targeting_kernel = True
                            if not targeting_kernel:
                                continue
                        count += 1
                        if count < index:
                            continue
                        
                        commit = syzkaller = config = syz_repro = log = c_repro = time_str = manager_str = report = offset = size = None
                        try:
                            manager = case.find('td', {"class": "manager"})
                            manager_str = manager.text
                        except Exception as e:
                            self.logger.exception("Failed to retrieve case \"manager\" {}: {}".format(url, e))
                        
                        try:
                            time = case.find('td', {"class": "time"})
                            time_str = time.text
                        except Exception as e:
                            self.logger.exception("Failed to retrieve case \"time\" {}: {}".format(url, e))
                        
                        try:
                            tags = case.find_all('td', {"class": "tag"})
                            m = re.search(r'id=([0-9a-z]*)', tags[0].next.attrs['href'])
                            if m is None:
                                m = re.search(r'([0-9a-z]{40})', tags[0].next.attrs['href'])
                            commit = m.groups()[0]
                        except Exception as e:
                            self.logger.exception("Failed to retrieve case \"commit\" {}: {}".format(url, e))
                            continue
                            
                        try:
                            self.logger.debug("Kernel commit: {}".format(commit))
                            m = re.search(r'([0-9a-z]{40})', tags[1].next.attrs['href'])
                            syzkaller = m.groups()[0]
                            self.logger.debug("Syzkaller commit: {}".format(syzkaller))
                        except Exception as e:
                            self.logger.exception("Failed to retrieve case \"syzkaller\" {}: {}".format(url, e))
                            continue

                        try:
                            config = syzbot_host_url + case.find('td', {"class": "config"}).next.attrs['href']
                            self.logger.debug("Config URL: {}".format(config))
                        except Exception as e:
                            self.logger.exception("Failed to retrieve case \"config\" {}: {}".format(url, e))
                            continue
                            
                        try:
                            repros = case.find_all('td', {"class": "repro"})
                            log = syzbot_host_url + repros[0].next.attrs['href']
                            self.logger.debug("Log URL: {}".format(log))
                            report = syzbot_host_url + repros[1].next.attrs['href']
                            self.logger.debug("Log URL: {}".format(report))
                        except Exception as e:
                            self.logger.exception("Failed to retrieve case \"report\" {}: {}".format(url, e))
                        
                        try:
                            r = request_get(report)
                            report_list = r.text.split('\n')
                            offset, size, _ = extract_vul_obj_offset_and_size(report_list)
                        except Exception as e:
                            self.logger.exception("Failed to retrieve case \"offset\" and \"size\" {}: {}".format(url, e))
                        
                        try:
                            syz_repro = syzbot_host_url + repros[2].next.attrs['href']
                            self.logger.debug("Testcase URL: {}".format(syz_repro))
                        except:
                            self.logger.debug("[Failed] {} Repro is missing".format(url))
                            if self.filter_by_syz_prog:
                                continue
                        try:
                            c_repro = syzbot_host_url + repros[3].next.attrs['href']
                            self.logger.debug("C prog URL: {}".format(c_repro))
                        except:
                            c_repro = None
                            self.logger.debug("No c prog found")
                            if self.filter_by_c_prog:
                                continue

                        return [commit, syzkaller, config, syz_repro, log, c_repro, time_str, manager_str, report, offset, size, kernel.text]
                break
        return []
    
    def _clone_target_repo(self, soup: BeautifulSoup):
        try:
            repo = soup.find('td', {'class': 'main'}).contents[2]
        except:
            self.logger.error("Can't find target repo")
            return None
        repo_url = "https://git.kernel.org/"+repo.attrs['href']
        if repo_url[-1] == '/':
            repo_url = repo_url[:-1]
        repo_name = repo_url.split('/')[-1].split('.')[0]
        if repo_name == 'linux':
            repo_name = 'upstream'
        repo_path = os.getcwd()+"/tools/linux-{}-0".format(repo_name)
        self.thread_lock.acquire()
        if not os.path.exists(repo_path):
            ret = clone_repo(repo_url, repo_path)
            if ret != 0:
                self.logger.error("Fail to clone kernel repo {}".format(repo_name))
                self.thread_lock.release()
                return None
        self.thread_lock.release()
        return repo_path

    def __get_table(self, url):
        self.logger.debug("Get table from {}".format(url))
        req = requests.request(method='GET', url=url)
        soup = BeautifulSoup(req.text, "html.parser")
        tables = soup.find_all('table', {"class": "list_table"})
        if len(tables) == 0:
            print("Fail to retrieve bug cases from list_table")
            return []
        return tables
    
    def _get_case_url(self, hash_val):
        if len(hash_val) != 40:
            url = syzbot_host_url + syzbot_bug_extid_url + hash_val
            r = request_get(url)
            if r.status_code == 404:
                url = syzbot_host_url + syzbot_bug_base_url + hash_val
        else:
            url = syzbot_host_url + syzbot_bug_base_url + hash_val
            r = request_get(url)
            if r.status_code == 404:
                url = syzbot_host_url + syzbot_bug_extid_url + hash_val
        return url
    
if __name__ == '__main__':
    pass
