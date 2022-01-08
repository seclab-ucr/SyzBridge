import pygsheets


from infra.tool_box import *
from plugins import AnalysisModule
from plugins.slack_bot import SlackBot

class GoogleSheets(AnalysisModule):
    NAME = "GoogleSheets"
    REPORT_START = "======================GoogleSheets Report======================"
    REPORT_END =   "==================================================================="
    REPORT_NAME = "Report_GoogleSheets"
    DEPENDENCY_PLUGINS = ["BugReproduce", "CapabilityCheck", "ModulesAnalysis", "Syzscope"]

    def __init__(self):
        super().__init__()
        self.report = ''
        self._prepared = False
        self.path_case_plugin = ''
        self._move_to_success = False
        self.sh = None
        
    def prepare(self):
        try:
            plugin = self.cfg.get_plugin(self.NAME)
            if plugin == None:
                self.logger.error("No such plugin: {}".format(self.NAME))
            credential = plugin.credential
        except KeyError:
            self.logger.error("Credential not found in config file")
            return False
        return self.prepare_on_demand(credential, self.args.proj)
    
    def prepare_on_demand(self, credential, proj):
        gc = pygsheets.authorize(credential)
        try:
            self.sh = gc.open(proj)
        except pygsheets.SpreadsheetNotFound:
            self.sh = gc.create(proj)
        self._prepared = True
        return True
    
    def success(self):
        return self._move_to_success

    def run(self):
        self.write_case_result(self.sh)
        return None
    
    def write_case_result(self, sh: pygsheets.Spreadsheet):
        self.data = {}
        wks = sh.sheet1
        self.create_banner(wks)
        self._write_hash(wks)
        self._write_title(wks)
        self._write_url(wks)
        self._write_reproducable(wks)
        self._write_module_analysis(wks)
        self._write_capability_check(wks)
        self._write_syzscope(wks)
        if self.manager.module_capable("SlackBot") and \
                (self.data['reproduce-by-normal'] != "" or self.data['reproduce-by-root'] != ""):
            bot = self._init_module(SlackBot())
            bot.prepare()
            blocks = bot.compose_blocks(self.data)
            bot.post_message(blocks)
    
    def create_banner(self, wks: pygsheets.Worksheet):
        if wks.get_value('A1') != 'hash':
            wks.update_value('A1', 'hash')
            wks.update_value('B1', 'title')
            wks.update_value('C1', 'url')
            wks.update_value('D1', 'reproducable-normal')
            wks.update_value('E1', 'reproducable-root')
            wks.update_value('F1', 'failed')
            wks.update_value('G1', 'module_analysis')
            wks.update_value('H1', 'capability_check')
            wks.update_value('I1', 'syzscope')
    
    def generate_report(self):
        final_report = "\n".join(self.report)
        self.logger.info(final_report)
        self._write_to(final_report, self.REPORT_NAME)
    
    def _write_hash(self, wks: pygsheets.Worksheet):
        hash_value = self.case['hash']
        self.data['hash'] = hash_value
        wks.insert_rows(1)
        wks.update_value('A2', hash_value)
    
    def _write_title(self, wks: pygsheets.Worksheet):
        title = self.case['title']
        self.data['title'] = title
        wks.update_value('B2', title)
    
    def _write_url(self, wks: pygsheets.Worksheet):
        url = "https://syzkaller.appspot.com/bug?id=" + self.data['hash']
        self.data['url'] = url
        wks.update_value('C2', "=HYPERLINK(\"https://syzkaller.appspot.com/bug?id=\"&A2, \"url\")")
    
    def _write_reproducable(self, wks: pygsheets.Worksheet):
        self.data['reproduce-by-normal'] = ""
        self.data['reproduce-by-root'] = ""
        self.data['failed-on'] = ""
        reproducable_regx = r'(debian|fedora|ubuntu) triggers a Kasan bug: ([A-Za-z0-9_: -]+) (by normal user|by root user)'
        failed_regx = r'(.+) fail to trigger the bug'
        path_report = os.path.join(self.path_case, "BugReproduce", "Report_BugReproduce")
        if os.path.exists(path_report):
            with open(path_report, "r") as f:
                report = f.readlines()
                for line in report:
                    if regx_match(reproducable_regx, line):
                        distro = regx_get(reproducable_regx, line, 0)
                        bug_title = regx_get(reproducable_regx, line, 1)
                        privilege = regx_get(reproducable_regx, line, 2)
                        if privilege == 'by normal user':
                            wks.update_value('D2', "{}-{}".format(distro, bug_title))
                            self.data['reproduce-by-normal'] += "{} ".format(distro)
                        if privilege == 'by root user':
                            wks.update_value('E2', "{}-{}".format(distro, bug_title))
                            self.data['reproduce-by-root'] += "{} ".format(distro)
                    if regx_match(failed_regx, line):
                        distros = regx_get(failed_regx, line, 0)
                        wks.update_value('F2', "{}".format(distros))
                        self.data['failed-on'] += "{} ".format(distros)

    def _write_module_analysis(self, wks: pygsheets.Worksheet):
        self.data['modules-analysis'] = ""
        pass

    def _write_capability_check(self, wks: pygsheets.Worksheet):
        res = {}
        regx1 = r'([A-Z_]+) seems to be bypassable'
        regx2 = r'([A-Z_]+) is checked by capable(), can not be ignored by user namespace'
        path_report = os.path.join(self.path_case, "CapabilityCheck", "Report_CapabilityCheck")
        if os.path.exists(path_report):
            with open(path_report, "r") as f:
                report = f.readlines()
                t = ''
                for line in report:
                    if regx_match(regx1, line):
                        cap_name = regx_get(regx1, line, 0)
                        if cap_name not in res:
                            res[cap_name] = 'bypassable'
                            t += line
                    if regx_match(regx2, line):
                        cap_name = regx_get(regx2, line, 0)
                        if cap_name not in res:
                            res[cap_name] = 'nope'
                            t += line
                wks.update_value('H2', t)
                self.data['capability-check'] = t
    
    def _write_syzscope(self, wks: pygsheets.Worksheet):
        self.data['syzscope'] = ""
        path_report = os.path.join(self.path_case, "Syzscope", "Report_Syzscope")
        if os.path.exists(path_report):
            with open(path_report, "r") as f:
                report = f.readlines()
                t = ''
                for line in report:
                    t += line
                wks.update_value('I2', t)
                self.data['syzscope'] = t

    def _write_to(self, content, name):
        file_path = "{}/{}".format(self.path_case_plugin, name)
        super()._write_to(content, file_path)

