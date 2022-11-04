import pygsheets


from infra.tool_box import *
from plugins import AnalysisModule
from plugins.slack_bot import SlackBot
from .error import CriticalModuleNotFinish

class GoogleSheets(AnalysisModule):
    NAME = "GoogleSheets"
    REPORT_START = "======================GoogleSheets Report======================"
    REPORT_END =   "==================================================================="
    REPORT_NAME = "Report_GoogleSheets"
    DEPENDENCY_PLUGINS = ["RawBugReproduce", "BugReproduce", "CapabilityCheck", "ModulesAnalysis", "Syzscope", "Fuzzing"]

    TYPE_FAILED = (1,1,1,1)
    TYPE_UNFINISHED = (0.9,0.23,0.58,0.8)
    TYPE_SUCCEED = (0.63,0.76,0.78,1.0) # rgba(162, 196, 201, 1)
    TYPE_SUCCEED_NEED_ADAPTATION = (0.27,0.5,0.55,1.0) # rgba(69, 129, 142, 1)

    NOT_TRIGGERED = 0
    TRIGGERED_BY_ROOT = 1
    TRIGGERED_BY_NORMAL = 2

    def __init__(self):
        super().__init__()
        self.sh = None
        self.idx = 0
        self.case_type = self.TYPE_FAILED
        self.triggered_by = self.NOT_TRIGGERED
        
    def prepare(self):
        try:
            plugin = self.cfg.get_plugin(self.NAME)
            if plugin == None:
                self.err_msg("No such plugin: {}".format(self.NAME))
            credential = plugin.credential
        except AttributeError:
            self.err_msg("Credential not found in config file")
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

    def handle_error(func):
        def inner(self):
            try:
                ret = func(self)
                return True
            except Exception as e:
                self.err_msg("GoogleSheets error: {}".format(e))
                return False
        return inner

    def run(self):
        self.write_case_result(self.sh)
        self.set_stage_text("Done")
        return True
    
    def write_case_result(self, sh: pygsheets.Spreadsheet):
        self.data = {}
        wks = sh.sheet1
        self.create_banner(wks)
        self.idx = self.case_in_sheets(wks)
        self._write_hash(wks)
        self._write_title(wks)
        self._write_url(wks)
        self._write_affect_distro(wks)

        if self.plugin_finished("BugReproduce"):
            self._write_reproducable(wks)
        else:
            self.write_failed_str_to_cell('E'+str(self.idx), wks)
            self.write_failed_str_to_cell('F'+str(self.idx), wks)
            self.write_failed_str_to_cell('G'+str(self.idx), wks)

        if self.plugin_finished("ModulesAnalysis"):
            self._write_module_analysis(wks)
        else:
            self.write_failed_str_to_cell('H'+str(self.idx), wks)

        if self.plugin_finished("CapabilityCheck"):
            self._write_capability_check(wks)
        else:
            self.write_failed_str_to_cell('I'+str(self.idx), wks)

        if self.plugin_finished("SyzScope"):
            self._write_syzscope(wks)
        else:
            self.write_failed_str_to_cell('J'+str(self.idx), wks)
        if self.plugin_finished("Fuzzing"):
            self._write_fuzzing(wks)
        else:
            self.write_failed_str_to_cell('K'+str(self.idx), wks)
        if self.plugin_finished("RawBugReproduce"):
            self._write_raw_reproducable(wks)
        else:
            self.write_failed_str_to_cell('L'+str(self.idx), wks)
        #self._render_cell_color('A'+str(self.idx), self.case_type, wks)
        self._render_row_coloer(wks)
        try:
            if self.manager.module_capable("SlackBot") and \
                    (self.data['reproduce-by-normal'] != "" or self.data['reproduce-by-root'] != ""):
                bot = self._init_module(SlackBot())
                bot.prepare()
                blocks = bot.compose_blocks(self.data)
                bot.post_message(blocks)
        except Exception as e:
            self.err_msg("slackbot error: {}".format(e))
    
    def create_banner(self, wks: pygsheets.Worksheet):
        if wks.get_value('A1') != 'hash':
            wks.update_value('A1', 'hash')
            wks.update_value('B1', 'title')
            wks.update_value('C1', 'url')
            wks.update_value('D1', 'affect-distros')
            wks.update_value('E1', 'reproducable-normal')
            wks.update_value('F1', 'reproducable-root')
            wks.update_value('G1', 'failed')
            wks.update_value('H1', 'module_analysis')
            wks.update_value('I1', 'capability_check')
            wks.update_value('J1', 'syzscope')
            wks.update_value('K1', 'fuzzing')
            wks.update_value('L1', 'raw_bug_reproduce')
    
    def generate_report(self):
        final_report = "\n".join(self.report)
        self.info_msg(final_report)
        self._write_to(final_report, self.REPORT_NAME)
    
    def set_history_status(self):
        if self.finish:
            self.set_stage_text("Done")
        else:
            self.set_stage_text("Failed")
    
    def case_in_sheets(self, wks: pygsheets.Worksheet):
        hash_value = self.case['hash']
        i = 2
        while i >= 0:
            val = wks.get_value('A'+str(i))
            if val == hash_value:
                return i
            if val == "":
                wks.insert_rows(1)
                return 2
            i+= 1 
    
    def _write_hash(self, wks: pygsheets.Worksheet):
        hash_value = self.case['hash']
        self.data['hash'] = hash_value
        wks.update_value('A'+str(self.idx), hash_value)
    
    def _write_title(self, wks: pygsheets.Worksheet):
        title = self.case['title']
        self.data['title'] = title
        wks.update_value('B'+str(self.idx), title)
    
    def _write_url(self, wks: pygsheets.Worksheet):
        url = "https://syzkaller.appspot.com/bug?id=" + self.data['hash']
        self.data['url'] = url
        wks.update_value('C'+str(self.idx), "=HYPERLINK(\"https://syzkaller.appspot.com/bug?id=\"&A{}, \"url\")".format(self.idx))
    
    def _write_affect_distro(self, wks: pygsheets.Worksheet):
        l = []
        for distro in self.cfg.get_distros():
            l.append(distro.distro_name)
        old_val = wks.get_value('D'+str(self.idx)) + '\n'
        wks.update_value('D'+str(self.idx), old_val+"\n".join(l))
    
    def _write_reproducable(self, wks: pygsheets.Worksheet):
        self.data['reproduce-by-normal'] = ""
        self.data['reproduce-by-root'] = ""
        self.data['failed-on'] = ""
        reproducable_regx = r'(.*) triggers a (Kasan )?bug: ([A-Za-z0-9_: -/]+) (by normal user|by root user)'
        failed_regx = r'(.+) fail to trigger the bug'
        path_report = os.path.join(self.path_case, "BugReproduce", "Report_BugReproduce")
        normal_text = ''
        root_text = ''
        fail_text = ''
        path_result = os.path.join(self.path_case, "BugReproduce", "results.json")
        result_json = json.load(open(path_result, 'r'))
        if os.path.exists(path_report):
            with open(path_report, "r") as f:
                report = f.readlines()
                for line in report:
                    if regx_match(reproducable_regx, line):
                        distro = regx_get(reproducable_regx, line, 0)
                        bug_title = regx_get(reproducable_regx, line, 2)
                        privilege = regx_get(reproducable_regx, line, 3)
                        if privilege == 'by normal user':
                            normal_text += "{}-{} {}\n".format(distro, bug_title, json.dumps(result_json[distro]))
                            self.data['reproduce-by-normal'] += "{} ".format(distro)
                            self.triggered_by = self.TRIGGERED_BY_NORMAL
                        if privilege == 'by root user':
                            root_text += "{}-{} {}\n".format(distro, bug_title, json.dumps(result_json[distro]))
                            self.data['reproduce-by-root'] += "{} ".format(distro)
                            self.triggered_by = self.TRIGGERED_BY_ROOT
                    if regx_match(failed_regx, line):
                        distros = regx_get(failed_regx, line, 0)
                        fail_text += "{}\n".format(distros)
                        self.data['failed-on'] += "{} ".format(distros)
        if normal_text != '' or root_text != '':
            self.case_type = self.TYPE_SUCCEED

        old_val = wks.get_value('E'+str(self.idx)) + '\n'
        wks.update_value('E'+str(self.idx), old_val + normal_text)
        old_val = wks.get_value('F'+str(self.idx)) + '\n'
        wks.update_value('F'+str(self.idx), old_val + root_text)
        old_val = wks.get_value('G'+str(self.idx)) + '\n'
        wks.update_value('G'+str(self.idx), old_val + fail_text)

    def _write_module_analysis(self, wks: pygsheets.Worksheet):
        self.data['modules-analysis'] = ""
        path_result = os.path.join(self.path_case, "ModulesAnalysis", "results.json")
        result_json = json.load(open(path_result, 'r'))
        v = json.dumps(result_json)
        old_val = wks.get_value('H'+str(self.idx)) + '\n'
        new_data = old_val + v
        if len(new_data) > 50000:
            new_data = new_data[:49999]
        wks.update_value('H'+str(self.idx), new_data)

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
                wks.update_value('I'+str(self.idx), t)
                self.data['capability-check'] = t
    
    def _write_syzscope(self, wks: pygsheets.Worksheet):
        self.data['syzscope'] = ""
        path_report = os.path.join(self.path_case, "Syzscope", "Report_Syzscope")
        if os.path.exists(path_report):
            with open(path_report, "r") as f:
                report = f.readlines()
                t = ''.join(report)
                wks.update_value('J'+str(self.idx), t)
                self.data['syzscope'] = t
    
    def _write_fuzzing(self, wks: pygsheets.Worksheet):
        self.data['fuzzing'] = ""
        path_report = os.path.join(self.path_case, "Fuzzing", "Report_Fuzzing")
        if os.path.exists(path_report):
            with open(path_report, "r") as f:
                report = f.readlines()
                t = ''.join(report)
                old_val = wks.get_value('K'+str(self.idx)) + '\n'
                wks.update_value('K'+str(self.idx), old_val + t)
                self.data['fuzzing'] = t
    
    def _write_raw_reproducable(self, wks: pygsheets.Worksheet):
        self.data['raw-reproduce-by-normal'] = ""
        self.data['raw-reproduce-by-root'] = ""
        self.data['raw-failed-on'] = ""
        reproducable_regx = r'(.*) triggers a (Kasan )?bug: ([A-Za-z0-9_: -/]+) (by normal user|by root user)'
        failed_regx = r'(.+) fail to trigger the bug'
        path_report = os.path.join(self.path_case, "RawBugReproduce", "Report_RawBugReproduce")
        normal_text = ''
        root_text = ''
        fail_text = ''
        triggered_by = self.NOT_TRIGGERED
        if os.path.exists(path_report):
            with open(path_report, "r") as f:
                report = f.readlines()
                for line in report:
                    if regx_match(reproducable_regx, line):
                        distro = regx_get(reproducable_regx, line, 0)
                        bug_title = regx_get(reproducable_regx, line, 2)
                        privilege = regx_get(reproducable_regx, line, 3)
                        if privilege == 'by normal user':
                            normal_text += "{}-{} by normal user\n".format(distro, bug_title)
                            self.data['raw-reproduce-by-normal'] += "{} ".format(distro)
                            triggered_by = self.TRIGGERED_BY_NORMAL
                        if privilege == 'by root user':
                            root_text += "{}-{} by root user\n".format(distro, bug_title)
                            self.data['raw-reproduce-by-root'] += "{} ".format(distro)
                            triggered_by = self.TRIGGERED_BY_ROOT
                    if regx_match(failed_regx, line):
                        distros = regx_get(failed_regx, line, 0)
                        fail_text += "{}\n".format(distros)
                        self.data['raw-failed-on'] += "{} ".format(distros)
        if root_text != '':
            old_val = wks.get_value('L'+str(self.idx)) + '\n'
            wks.update_value('L'+str(self.idx), old_val + root_text)
        if normal_text != '':
            old_val = wks.get_value('L'+str(self.idx)) + '\n'
            wks.update_value('L'+str(self.idx), old_val + normal_text)
        if self.triggered_by != self.NOT_TRIGGERED:
            if triggered_by == self.NOT_TRIGGERED or \
                    (triggered_by == self.TRIGGERED_BY_ROOT and self.triggered_by == self.TRIGGERED_BY_NORMAL):
                self.case_type = self.TYPE_SUCCEED_NEED_ADAPTATION
    
    def write_failed_str_to_cell(self, pos, wks):
        old_val = wks.get_value(pos) + '\n' + "failed"
        self._write_to_cell(pos, old_val, wks)

    def _write_to_cell(self, pos, text, wks):
        wks.update_value(pos, text)

    def _render_row_coloer(self, wks: pygsheets.Worksheet):
        for i in range(0, 26):
            ch = chr(ord('A') + i)
            cell = wks.cell(ch+str(self.idx))
            cell.color = self.case_type
    
    def _render_cell_color(self, pos, color, wks: pygsheets.Worksheet):
        cell = wks.cell(pos)
        cell.color = color

    def _write_to(self, content, name):
        file_path = "{}/{}".format(self.path_case_plugin, name)
        super()._write_to(content, file_path)
    
    def cleanup(self):
        super().cleanup()

