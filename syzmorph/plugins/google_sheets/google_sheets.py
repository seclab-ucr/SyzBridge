import pygsheets
import time
import traceback

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
    DARK_ORANGE = (0.90, 0.56, 0.219, 1)
    DARK_GREEN = (0.415, 0.658, 0.309, 1)
    DARK_CYAN = (0.27, 0.505, 0.556, 1)
    LIGHT_CYAN = (0.462, 0.641, 0.686, 1)

    NOT_TRIGGERED = 0
    TRIGGERED_BY_ROOT = 1
    TRIGGERED_BY_NORMAL = 2

    def __init__(self):
        super().__init__()
        self.sh = None
        self.idx = 0
        self.skip_priv_page = False
        self.case_type = self.TYPE_FAILED
        self.triggered_by = self.NOT_TRIGGERED
        self.private_sheet = None
        self.n_distro = 0
        self.distro2idx = []
        self.p_wks: pygsheets.Spreadsheet = None
        self.main_sheet = None
        self.m_wks: pygsheets.Spreadsheet = None
        
    def prepare(self):
        plugin = self.cfg.get_plugin(self.NAME)
        if plugin == None:
            self.err_msg("No such plugin: {}".format(self.NAME))
        try:
            credential = plugin.credential
        except AttributeError:
            self.err_msg("Credential not found in config file")
            return False
        try:
            self.main_sheet = plugin.main_sheet
        except AttributeError:
            self.err_msg("main_sheet is not specified in configuration")
            return False
        try:
            self.private_sheet = plugin.private_sheet
        except AttributeError:
            pass
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
            for _ in range(0, 3):
                try:
                    ret = func(self)
                    return ret
                except Exception as e:
                    self.err_msg("GoogleSheets error: {}".format(e))
                    tb = traceback.format_exc()
                    self.logger.error(tb)
                    # Sometimes the request is exceed the limits set by Google
                    time.sleep(60)
        return inner

    def sleeper(func):
        def inner(self, *args):
            ret = func(self, *args)
            time.sleep(3)
            return ret
        return inner

    @handle_error
    def run(self):
        self.write_case_result(self.sh)
        self.set_stage_text("Done")
        return True
    
    def write_case_result(self, sh: pygsheets.Spreadsheet):
        self.data = {}
        if self.private_sheet != None:
            try:
                self.p_wks = sh.worksheet_by_title(self.private_sheet)
            except pygsheets.WorksheetNotFound:
                self.p_wks = sh.add_worksheet(self.private_sheet)
        try:
            self.m_wks = sh.worksheet_by_title(self.main_sheet)
        except pygsheets.WorksheetNotFound:
            self.m_wks = sh.add_worksheet(self.main_sheet)

        if not self.skip_priv_page:
            self.fill_sheet(self.p_wks)
            try:
                if self.manager.module_capable("SlackBot") and \
                        (self.data['reproduce-by-normal'] != []):
                    bot = self._init_module(SlackBot())
                    bot.prepare()
                    blocks = bot.compose_blocks(self.data)
                    bot.post_message(blocks)
            except Exception as e:
                self.err_msg("slackbot error: {}".format(e))
        
        self.skip_priv_page = True
        self.fill_sheet(self.m_wks, append=True)
        return
    
    def fill_sheet(self, wks: pygsheets.Spreadsheet, append=False):
        self.create_banner(wks)
        self.idx = self.case_in_sheets(wks)
        self._write_hash(wks)
        self._write_title(wks)
        self._write_url(wks)
        self._write_affect_distro(wks, append)

        if self.plugin_finished("RawBugReproduce"):
            self._write_raw_reproducable(wks, append)
        else:
            self.write_failed_str_to_cell('S'+str(self.idx), wks)
        if self.plugin_finished("BugReproduce"):
            self._write_reproducable(wks, append)
        else:
            self.write_failed_str_to_cell('E'+str(self.idx), wks)
            self.write_failed_str_to_cell('F'+str(self.idx), wks)
            self.write_failed_str_to_cell('G'+str(self.idx), wks)

        if self.plugin_finished("ModulesAnalysis"):
            self._write_module_analysis(wks, append)
        else:
            self.write_failed_str_to_cell('Q'+str(self.idx), wks)

        if self.plugin_finished("CapabilityCheck"):
            self._write_capability_check(wks)
        else:
            self.write_failed_str_to_cell('R'+str(self.idx), wks)
        
        if self.plugin_finished("Fuzzing"):
            self._write_fuzzing(wks)
        
        if self.plugin_finished("Syzscope"):
            self._write_syzscope(wks)

        if self.plugin_finished("SyzFeatureMinimize"):
            self._write_syz_feature_minimize(wks)
        else:
            self.write_failed_str_to_cell('M'+str(self.idx), wks)
        self._render_cell_color('A'+str(self.idx), self.case_type, wks)
        #self._render_row_coloer(wks) # Too many requests
    
    @sleeper
    def create_banner(self, wks: pygsheets.Worksheet):
        if wks.get_value('A1') != 'hash':
            wks.update_value('A1', 'hash')
            wks.update_value('B1', 'title')
            wks.update_value('C1', 'url')
            wks.update_value('D1', 'affect-distros')
            wks.update_value('E1', 'reproducable-normal')
            wks.update_value('F1', 'reproducable-root')
            wks.update_value('G1', 'failed')
            wks.update_value('H1', 'namespace')
            wks.update_value('I1', 'module loading')
            wks.update_value('J1', 'skip preparation')
            wks.update_value('K1', 'repeat')
            wks.update_value('L1', 'loop device')
            wks.update_value('M1', 'module require')
            wks.update_value('N1', 'Triggered')
            wks.update_value('O1', 'Privilege Adaptation')
            wks.update_value('P1', 'Env Adaptation')
            wks.update_value('Q1', 'module_analysis')
            wks.update_value('R1', 'capability_check')
            wks.update_value('S1', 'raw_bug_reproduce')
            wks.update_value('T1', 'syz_feature_minimize')
            wks.update_value('U1', 'Raw trigger by normal')
            self._render_adaptation_cells(wks)
    
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
        self.n_distro = len(self.cfg.get_distros())
        while i >= 0:
            val = wks.get_value('A'+str(i))
            title = wks.get_value('B'+str(i))
            if val == hash_value:
                wks.insert_rows(i-1, number=self.n_distro)
                return i
            if val == "":
                wks.insert_rows(1, number=self.n_distro)
                return 2
            try:
                n_line = int(regx_get(r'(\d+):.*', title, 0))
            except:
                return 2
            i+= n_line
    
    def _merge_cell(self, column, wks):
        if self.n_distro > 1:
            wks.merge_cells(column+str(self.idx), column+str(self.idx+self.n_distro-1), merge_type='MERGE_COLUMNS')
    
    @sleeper
    def _write_hash(self, wks: pygsheets.Worksheet):
        hash_value = self.case['hash']
        self.data['hash'] = hash_value
        self._merge_cell('A', wks)
        wks.update_value('A'+str(self.idx), hash_value)
    
    @sleeper
    def _write_title(self, wks: pygsheets.Worksheet):
        title = str(self.n_distro) + ":" + self.case['title']
        self.data['title'] = title
        self._merge_cell('B', wks)
        wks.update_value('B'+str(self.idx), title)
    
    @sleeper
    def _write_url(self, wks: pygsheets.Worksheet):
        url = "https://syzkaller.appspot.com/bug?id=" + self.data['hash']
        self.data['url'] = url
        self._merge_cell('C', wks)
        wks.update_value('C'+str(self.idx), "=HYPERLINK(\"https://syzkaller.appspot.com/bug?id=\"&A{}, \"url\")".format(self.idx))
    
    @sleeper
    def _write_affect_distro(self, wks: pygsheets.Worksheet, append):
        for distro in self.cfg.get_distros():
            self.distro2idx.append(distro.distro_name)
            wks.update_value('D'+self.distro_idx(distro.distro_name), distro.distro_name)
            wks.update_value('H'+self.distro_idx(distro.distro_name), False)
            wks.update_value('I'+self.distro_idx(distro.distro_name), False)
            wks.update_value('J'+self.distro_idx(distro.distro_name), False)
            wks.update_value('K'+self.distro_idx(distro.distro_name), False)
            wks.update_value('L'+self.distro_idx(distro.distro_name), False)
            wks.update_value('M'+self.distro_idx(distro.distro_name), False)
            wks.update_value('N'+self.distro_idx(distro.distro_name), False)
    
    @sleeper
    def _write_reproducable(self, wks: pygsheets.Worksheet, append):
        self.data['reproduce-by-normal'] = []
        self.data['reproduce-by-root'] = []
        self.data['failed-on'] = []
        reproducable_regx = r'(.*) triggers a (Kasan )?bug: ([A-Za-z0-9_: -/=]+) (by normal user|by root user)'
        failed_regx = r'(.+) fail to trigger the bug'
        path_report = os.path.join(self.path_case, "BugReproduce", "Report_BugReproduce")
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
                            wks.update_value('E'+self.distro_idx(distro), "{}-{} {}".format(distro, bug_title, json.dumps(result_json[distro])))
                            self.data['reproduce-by-normal'].append(format(distro))
                            self.triggered_by = self.TRIGGERED_BY_NORMAL
                            self.case_type = self.TYPE_SUCCEED
                            if 'raw-reproduce-by-normal' not in self.data or distro not in self.data['raw-reproduce-by-normal']:
                                if result_json[distro]['namespace']:
                                    self._set_cell_to_true('H'+self.distro_idx(distro), wks)
                                if 'tun' in result_json[distro]['skip_funcs'] or 'devlink_pci' in result_json[distro]['skip_funcs']:
                                    self._set_cell_to_true('J' + self.distro_idx(distro), wks)
                            if 'unprivileged_module_loading' in  result_json[distro] and result_json[distro]['unprivileged_module_loading']:
                                self._set_cell_to_true('I'+self.distro_idx(distro), wks)
                            self._check_env_adaptation(self.idx++self.distro2idx.index(distro), wks, result_json, distro)
                            self._set_cell_to_true('N' + self.distro_idx(distro), wks)
                        if privilege == 'by root user':
                            wks.update_value('F'+self.distro_idx(distro), "{}-{} {}".format(distro, bug_title, json.dumps(result_json[distro])))
                            self.data['reproduce-by-root'].append(format(distro))
                            self.triggered_by = self.TRIGGERED_BY_ROOT
                            self.case_type = self.TYPE_SUCCEED
                            self._check_env_adaptation(self.distro_idx(distro), wks, result_json, distro)
                            self._set_cell_to_true('N' + self.distro_idx(distro), wks)
                    if regx_match(failed_regx, line):
                        distros = regx_get(failed_regx, line, 0)
                        for distro in distros.split(' '):
                            if distro == '':
                                continue
                            wks.update_value('G'+str(self.distro_idx(distro)), distro)
                            self.data['failed-on'].append(format(distro))

    @sleeper
    def _write_module_analysis(self, wks: pygsheets.Worksheet, append):
        self.data['modules-analysis'] = ""
        path_result = os.path.join(self.path_case, "ModulesAnalysis", "results.json")
        result_json = json.load(open(path_result, 'r'))
        self._merge_cell('Q', wks)
        v = json.dumps(result_json)
        if append:
            old_val = wks.get_value('Q'+str(self.idx)) + '\n'
            new_data = old_val + v
            if len(new_data) > 50000:
                new_data = new_data[:49999]
            wks.update_value('Q'+str(self.idx), new_data)
        else:
            new_data = v
            if len(new_data) > 50000:
                new_data = new_data[:49999]
            wks.update_value('Q'+str(self.idx), new_data)
            
    @sleeper
    def _write_capability_check(self, wks: pygsheets.Worksheet):
        res = {}
        regx1 = r'([A-Z_]+) seems to be bypassable'
        regx2 = r'([A-Z_]+) is checked by capable(), can not be ignored by user namespace'
        path_report = os.path.join(self.path_case, "CapabilityCheck", "Report_CapabilityCheck")
        self._merge_cell('R', wks)
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
                wks.update_value('R'+str(self.idx), t)
                self.data['capability-check'] = t
    
    @sleeper
    def _write_syzscope(self, wks: pygsheets.Worksheet):
        self.data['syzscope'] = ""
        path_report = os.path.join(self.path_case, "Syzscope", "Report_Syzscope")
        if os.path.exists(path_report):
            with open(path_report, "r") as f:
                report = f.readlines()
                t = ''.join(report)
                wks.update_value('J'+str(self.idx), t)
                self.data['syzscope'] = t
    
    @sleeper
    def _write_fuzzing(self, wks: pygsheets.Worksheet):
        self.data['fuzzing'] = ""
        path_report = os.path.join(self.path_case, "Fuzzing", "Report_Fuzzing")
        if os.path.exists(path_report):
            with open(path_report, "r") as f:
                report = f.readlines()
                t = ''.join(report)
                wks.update_value('K'+str(self.idx), t)
                self.data['fuzzing'] = t
    
    @sleeper
    def _write_raw_reproducable(self, wks: pygsheets.Worksheet, append):
        self.data['raw-reproduce-by-normal'] = []
        self.data['raw-reproduce-by-root'] = []
        self.data['raw-failed-on'] = []
        reproducable_regx = r'(.*) triggers a (Kasan )?bug: ([A-Za-z0-9_: -/]+) (by normal user|by root user)'
        failed_regx = r'(.+) fail to trigger the bug'
        path_report = os.path.join(self.path_case, "RawBugReproduce", "Report_RawBugReproduce")
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
                            wks.update_value('S'+self.distro_idx(distro), "{}-{} by normal user\n".format(distro, bug_title))
                            self.data['raw-reproduce-by-normal'].append(distro)
                            triggered_by = self.TRIGGERED_BY_NORMAL
                            self._set_cell_to_true('N' + self.distro_idx(distro), wks)
                            self._set_cell_to_true('U'+self.distro_idx(distro), wks)
                        if privilege == 'by root user':
                            wks.update_value('S'+self.distro_idx(distro), "{}-{} by root user\n".format(distro, bug_title))
                            self.data['raw-reproduce-by-root'].append(distro)
                            triggered_by = self.TRIGGERED_BY_ROOT
                            self._set_cell_to_true('N' + self.distro_idx(distro), wks)
                    if regx_match(failed_regx, line):
                        distros = regx_get(failed_regx, line, 0)
                        for distro in distros.split(' '):
                            if distro == '':
                                continue
                            self.data['raw-failed-on'].append(distro)
        if self.triggered_by != self.NOT_TRIGGERED:
            if triggered_by == self.NOT_TRIGGERED or \
                    (triggered_by == self.TRIGGERED_BY_ROOT and self.triggered_by == self.TRIGGERED_BY_NORMAL):
                self.case_type = self.TYPE_SUCCEED_NEED_ADAPTATION
    
    @sleeper
    def _write_syz_feature_minimize(self, wks: pygsheets.Worksheet):
        path_results = os.path.join(self.path_case, "SyzFeatureMinimize", "results.json")
        if os.path.exists(path_results):
            result_json = json.load(open(path_results, "r"))
            v = json.dumps(result_json)
            wks.update_value('T'+str(self.idx), v)
    
    def _check_env_adaptation(self, idx, wks, result, distro):
        if distro not in self.data['raw-failed-on']:
            return
        path_testcase = os.path.join(self.path_case, "SyzFeatureMinimize", "testcase")
        if self._is_repeat(path_testcase, result[distro]):
            self._set_cell_to_true('K' + str(idx), wks)
        if self._skip_preparation(result[distro]):
            self._set_cell_to_true('J' + str(idx), wks)
        if self._check_loop_device(result[distro]):
            self._set_cell_to_true('L' + str(idx), wks)
        if self._module_missing(result[distro]):
            self._set_cell_to_true('M' + str(idx), wks)
    
    def _is_repeat(self, path_testcase, result):
        if not result['repeat']:
            return False
        with open(path_testcase, 'r') as f:
            text = f.readlines()
            for line in text:
                if line.find('{') != -1 and line.find('}') != -1:
                    pm = {}
                    try:
                        pm = json.loads(line[1:])
                    except json.JSONDecodeError:
                        pm = syzrepro_convert_format(line[1:])
                    return 'repeat' not in pm or not pm['repeat']
        return False

    def _skip_preparation(self, result):
        return 'setup_usb' in result['skip_funcs'] or 'setup_leak' in result['skip_funcs']
    
    def _check_loop_device(self, result):
        return 'loop_dev' in  result['device_tuning']
    
    def _module_missing(self, result):
        return len(result['missing_module']) > 0 or len(result['env_modules']) > 0
    
    def _gather_adaptation(self, idx, wks: pygsheets.Worksheet):
        wks.update_value('O' + str(idx), "=OR(H2,I2)")
        wks.update_value('P' + str(idx), "=OR(J2,K2,L2,M2)")

    def write_failed_str_to_cell(self, pos, wks):
        old_val = wks.get_value(pos) + '\n' + "failed"
        self._write_to_cell(pos, old_val, wks)

    def _set_cell_to_true(self, pos, wks: pygsheets.Worksheet):
        wks.update_value(pos, True)

    def _write_to_cell(self, pos, text, wks):
        wks.update_value(pos, text)

    def _render_row_coloer(self, wks: pygsheets.Worksheet):
        for i in range(0, 26):
            ch = chr(ord('A') + i)
            cell = wks.cell(ch+str(self.idx))
            cell.color = self.case_type
    
    def _render_adaptation_cells(self, wks):
        self._render_cell_color('H1', self.DARK_ORANGE, wks)
        self._render_cell_color('I1', self.DARK_ORANGE, wks)
        self._render_cell_color('J1', self.DARK_GREEN, wks)
        self._render_cell_color('K1', self.DARK_GREEN, wks)
        self._render_cell_color('L1', self.DARK_GREEN, wks)
        self._render_cell_color('M1', self.DARK_GREEN, wks)
        self._render_cell_color('N1', self.DARK_CYAN, wks)
        self._render_cell_color('O1', self.DARK_ORANGE, wks)
        self._render_cell_color('P1', self.DARK_GREEN, wks)
        self._render_cell_color('U1', self.LIGHT_CYAN, wks)

    def _render_cell_color(self, pos, color, wks: pygsheets.Worksheet):
        cell = wks.cell(pos)
        cell.color = color

    def _write_to(self, content, name):
        file_path = "{}/{}".format(self.path_case_plugin, name)
        super()._write_to(content, file_path)
    
    def cleanup(self):
        super().cleanup()

    def distro_idx(self, distro):
        return str(self.idx+self.distro2idx.index(distro))