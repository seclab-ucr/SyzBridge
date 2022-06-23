from subprocess import Popen, PIPE, STDOUT
import requests
import time
import pandas as pd
import re, os
from syzmorph.infra.config.config import Config

from syzmorph.infra.tool_box import clone_repo, init_logger, regx_get, regx_match, request_get, extract_vul_obj_offset_and_size
from bs4 import BeautifulSoup
from bs4 import element
from .error import *

syzbot_bug_base_url = "bug?id="
syzbot_host_url = "https://syzkaller.appspot.com/"
num_of_elements = 8

class Crawler:
    def __init__(self,
                 url="https://syzkaller.appspot.com/upstream/fixed",
                 keyword=[], max_retrieve=99999, filter_by_reported="", log_path = ".", cfg=None,
                 filter_by_closed="", filter_by_c_prog=False, filter_by_fixes_tag=False, filter_by_kernel=[], include_high_risk=True, debug=False):
        self.url = url
        if type(keyword) == list:
            self.keyword = keyword
        else:
            print("keyword must be a list")
        self.max_retrieve = max_retrieve
        self.cases = {}
        self.patches = {}
        self.patch_info = {}
        self.include_high_risk = include_high_risk
        self.logger = init_logger(log_path + "/syzbot.log", debug = debug, propagate=True)
        self.filter_by_reported = [-1, -1]
        self.filter_by_closed = [-1, -1]
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
        self.filter_by_c_prog = filter_by_c_prog
        self.filter_by_fixes_tag = filter_by_fixes_tag
        self.filter_by_kernel = filter_by_kernel
        if cfg != None:
            self.cfg: Config = cfg
        else:
            self.cfg = None

    def run(self):
        cases_hash, high_risk_impacts = self.gather_cases()
        for each in cases_hash:
            if 'Patch' in each:
                patch_url = each['Patch']
                if patch_url in self.patches or \
                    (patch_url in high_risk_impacts and not self.include_high_risk):
                    continue
                self.patches[patch_url] = True
            if self.filter_by_fixes_tag:
                if not self.check_excluded_distro(each['Hash'], patch_url):
                    self.logger.debug("{} does not have a fixes tag".format(each['Hash']))
                    continue
            if self.retreive_case(each['Hash']) != -1:
                self.cases[each['Hash']]['title'] = each['Title']
                self.cases[each['Hash']]['patch'] = self.patch_info

    def get_patch_url(self, hash):
        url = syzbot_host_url + syzbot_bug_base_url + hash
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
    
    def check_excluded_distro(self, hash_val, patch_url):
        req = requests.request(method='GET', url=patch_url)
        soup = BeautifulSoup(req.text, "html.parser")
        self.patch_info = {'url': None, 'fixes':[], 'date':None}
        self.patch_info['url'] = patch_url
        patch_hash = patch_url.split("id=")[1]
        patch_date = self.get_linux_commit_date_offline(patch_hash, soup)
        if patch_date == None:
            self.patch_info['date'] = None
        else:
            self.patch_info['date'] = patch_date.strftime("%Y-%m-%d")
        try:
            msg = soup.find('div', {'class': 'commit-msg'}).text
            for line in msg.split('\n'):
                if line.startswith('Fixes:'):
                    fix_hash = regx_get(r'Fixes: ([a-z0-9]+)', line, 0)
                    commit_date = self.get_linux_commit_date_offline(fix_hash, soup)
                    if commit_date == None:
                        commit_date = self.get_linux_commit_date_online(fix_hash)
                        if commit_date == None:
                            continue
                    self.patch_info['fixes'] = {'hash': fix_hash, 'date': commit_date.strftime("%Y-%m-%d"), 'exclude': []}
                    self.logger.debug("Fix tag {}: {}".format(fix_hash, commit_date))

                    # We want to save all fixes tag info
                    # don't return too early
                    if self.cfg == None:
                        continue
                    base_version = self.closest_tag(fix_hash, soup)
                    if base_version == None:
                        continue
                    for distro in self.cfg.get_distros():
                        if not self.is_newer_version(base_version, distro.distro_version):
                            self.patch_info['fixes']['exclude'].append(distro.distro_name)
        except Exception as e:
            self.logger.error("Error parsing fix tag for {}: {}".format(hash_val, e))
        return self.patch_info['fixes'] != []

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
        return self.get_linux_commit_date_in_repo(repo_path, hash_val)
    
    def get_linux_commit_date_in_repo(self, repo_path, hash_val):
        p = Popen(["git", "log", hash_val, "--pretty=format:\"%H %ad\"", "--date=short", "-n", "1"],
            cwd=repo_path,
            stdout=PIPE, 
            stderr=STDOUT)
        with p.stdout as pipe:
            for line in iter(pipe.readline, b''):
                line = line.strip().decode('utf-8')
                time_stamp = regx_get(r'[a-z0-9]{40} (\d{4}-\d{2}-\d{2})', line, 0)
                return pd.to_datetime(time_stamp)
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

    def run_one_case(self, hash):
        self.logger.info("retreive one case: %s",hash)
        patch_url = self.get_patch_url(hash)
        if self.retreive_case(hash) == -1:
            return
        if self.filter_by_fixes_tag:
            if not self.check_excluded_distro(hash, patch_url):
                self.logger.error("{} does not have a fixes tag".format(hash))
                return
        self.cases[hash]['title'] = self.get_title_of_case(hash)
        self.cases[hash]['patch'] = self.patch_info
        return self.cases[hash]
    
    def get_title_of_case(self, hash=None, text=None):
        if hash==None and text==None:
            self.logger.info("No case given")
            return None
        if hash!=None:
            url = syzbot_host_url + syzbot_bug_base_url + hash
            req = requests.request(method='GET', url=url)
            soup = BeautifulSoup(req.text, "html.parser")
        else:
            soup = BeautifulSoup(text, "html.parser")
        title = soup.body.b.contents[0]
        return title

    def retreive_case(self, hash):
        self.cases[hash] = {}
        detail = self.request_detail(hash)
        if len(detail) < num_of_elements:
            self.logger.error("Failed to get detail of a case {}{}{}".format(syzbot_host_url, syzbot_bug_base_url, hash))
            self.cases.pop(hash)
            return -1
        self.cases[hash]["commit"] = detail[0]
        self.cases[hash]["syzkaller"] = detail[1]
        self.cases[hash]["config"] = detail[2]
        self.cases[hash]["syz_repro"] = detail[3]
        self.cases[hash]["log"] = detail[4]
        self.cases[hash]["c_repro"] = detail[5]
        self.cases[hash]["time"] = detail[6]
        self.cases[hash]["manager"] = detail[7]
        self.cases[hash]["report"] = detail[8]
        self.cases[hash]["vul_offset"] = detail[9]
        self.cases[hash]["obj_size"] = detail[10]
        self.cases[hash]["kernel"] = detail[11]
        self.cases[hash]["hash"] = hash

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
        href = title.next.attrs['href']
        hash = href[8:]
        crash['Hash'] = hash
        return crash

    def request_detail(self, hash, index=1):
        self.logger.debug("\nDetail: {}{}{}".format(syzbot_host_url, syzbot_bug_base_url, hash))
        url = syzbot_host_url + syzbot_bug_base_url + hash
        tables = self.__get_table(url)
        if tables == []:
            print("error occur in request_detail: {}".format(hash))
            self.logger.error("[Failed] {} error occur in request_detail".format(url))
            return []
        count = 0
        for table in tables:
            if table.caption.text.find('Crash') != -1:
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
                            self.logger.info("Failed to retrieve case \"manager\" {}{}{}".format(syzbot_host_url, syzbot_bug_base_url, hash))
                            self.logger.debug(e)
                        
                        try:
                            time = case.find('td', {"class": "time"})
                            time_str = time.text
                        except Exception as e:
                            self.logger.info("Failed to retrieve case \"time\" {}{}{}".format(syzbot_host_url, syzbot_bug_base_url, hash))
                            self.logger.debug(e)
                        
                        try:
                            tags = case.find_all('td', {"class": "tag"})
                            m = re.search(r'id=([0-9a-z]*)', tags[0].next.attrs['href'])
                            if m is None:
                                m = re.search(r'commits\/([0-9a-z]*)', tags[0].next.attrs['href'])
                            commit = m.groups()[0]
                        except Exception as e:
                            self.logger.info("Failed to retrieve case \"commit\" {}{}{}".format(syzbot_host_url, syzbot_bug_base_url, hash))
                            self.logger.debug(e)
                            continue
                            
                        try:
                            self.logger.debug("Kernel commit: {}".format(commit))
                            m = re.search(r'commits\/([0-9a-z]*)', tags[1].next.attrs['href'])
                            syzkaller = m.groups()[0]
                            self.logger.debug("Syzkaller commit: {}".format(syzkaller))
                        except Exception as e:
                            self.logger.info("Failed to retrieve case \"syzkaller\" {}{}{}".format(syzbot_host_url, syzbot_bug_base_url, hash))
                            self.logger.debug(e)
                            continue

                        try:
                            config = syzbot_host_url + case.find('td', {"class": "config"}).next.attrs['href']
                            self.logger.debug("Config URL: {}".format(config))
                        except Exception as e:
                            self.logger.info("Failed to retrieve case \"config\" {}{}{}".format(syzbot_host_url, syzbot_bug_base_url, hash))
                            self.logger.debug(e)
                            continue
                            
                        try:
                            repros = case.find_all('td', {"class": "repro"})
                            log = syzbot_host_url + repros[0].next.attrs['href']
                            self.logger.debug("Log URL: {}".format(log))
                            report = syzbot_host_url + repros[1].next.attrs['href']
                            self.logger.debug("Log URL: {}".format(report))
                        except Exception as e:
                            self.logger.info("Failed to retrieve case \"report\" {}{}{}".format(syzbot_host_url, syzbot_bug_base_url, hash))
                            self.logger.debug(e)
                        
                        try:
                            r = request_get(report)
                            report_list = r.text.split('\n')
                            offset, size, _ = extract_vul_obj_offset_and_size(report_list)
                        except Exception as e:
                            self.logger.info("Failed to retrieve case \"offset\" and \"size\" {}{}{}".format(syzbot_host_url, syzbot_bug_base_url, hash))
                            self.logger.debug(e)
                        
                        try:
                            syz_repro = syzbot_host_url + repros[2].next.attrs['href']
                            self.logger.debug("Testcase URL: {}".format(syz_repro))
                        except:
                            self.logger.debug("[Failed] {} Repro is missing".format(url))
                            break
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
        if not os.path.exists(repo_path):
            ret = clone_repo(repo_url, repo_path)
            if ret != 0:
                self.logger.error("Fail to clone kernel repo {}".format(repo_name))
                return None
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

if __name__ == '__main__':
    pass