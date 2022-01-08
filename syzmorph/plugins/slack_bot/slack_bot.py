from slack import WebClient
from slack.errors import *

from infra.tool_box import init_logger
from plugins import AnalysisModule


class SlackBot(AnalysisModule):
    NAME = "SlackBot"
    REPORT_START = "======================SlackBot Report======================"
    REPORT_END =   "==================================================================="
    REPORT_NAME = "Report_SlackBot"
    DEPENDENCY_PLUGINS = []

    def __init__(self):
        super().__init__()
        self.report = ''
        self.client = None
        self.conversation_id = None
        self._prepared = False
        self.path_case_plugin = ''
        self._move_to_success = False
        
    def prepare(self):
        try:
            plugin = self.cfg.get_plugin(self.NAME)
            if plugin == None:
                self.logger.error("No such plugin {}".format(self.NAME))
            slack_token = plugin.slack_token
            channel = plugin.channel
        except KeyError:
            self.logger.error("Failed to get slack token or channel")
            return False
        return self.prepare_on_demand(slack_token, channel)
    
    def prepare_on_demand(self, slack_token, channel):
        try:
            self.client = WebClient(token=slack_token)
            res = self.client.conversations_list()
            for each in res['channels']:
                if each['name'] == channel:
                    self.conversation_id = each['id']
                    self.logger.info("Find target channel: {}".format(channel))
                    break
        except SlackApiError as e:
            self.logger.error("Failed to prepare SlackBot: {}".format(e))
            return False
        self._prepared = True
        return True
    
    def success(self):
        return self._move_to_success

    def run(self):
        return None
    
    def compose_blocks(self, data: dict):
        """
        hash, title, url, reproduce-by-normal, reproduce-by-root, failed-on, modules-analysis, capability-check
        """
        block = []
        header = {}
        header['type'] = 'header'
        header['text'] = {'type': 'plain_text', 'text': data['hash']}
        block.append(header)

        bug_titile_section = {}
        bug_titile_section['type'] = 'section'
        bug_titile_section['text'] = {'type': 'mrkdwn', 'text': '*Bug Title:*\n{}'.format(data['title'])}
        block.append(bug_titile_section)

        bug_dashboard_section = {}
        bug_dashboard_section['type'] = 'section'
        bug_dashboard_section['text'] = {'type': 'mrkdwn', 'text': '*Bug Dashboard:*\n<{}|{}>'.format(data['url'], data['url'])}
        block.append(bug_dashboard_section)
        block.append({'type': 'divider'})

        reproduce_section = {}
        reproduce_section['type'] = 'section'
        reproduce_section['fields'] = [{'type': 'mrkdwn', 'text': '*Reproduced by normal user:*\n{}'.format(data['reproduce-by-normal'])},
                                        {'type': 'mrkdwn', 'text': '*Reproduced by root user:*\n{}'.format(data['reproduce-by-root'])}]
        block.append(reproduce_section)

        failed_on_section = {}
        failed_on_section['type'] = 'section'
        failed_on_section['text'] = {'type': 'mrkdwn', 'text': '*Failed on:*\n{}'.format(data['failed-on'])}
        block.append(failed_on_section)
        block.append({'type': 'divider'})

        modules_analysis_section = {}
        modules_analysis_section['type'] = 'section'
        modules_analysis_section['text'] = {'type': 'mrkdwn', 'text': '*Moudles Analysis:*\n{}'.format(data['modules-analysis'])}
        block.append(modules_analysis_section)

        capability_check_section = {}
        capability_check_section['type'] = 'section'
        capability_check_section['text'] = {'type': 'mrkdwn', 'text': '*Capability Check:*\n{}'.format(data['capability-check'])}
        block.append(capability_check_section)

        syzscope_section = {}
        syzscope_section['type'] = 'section'
        syzscope_section['text'] = {'type': 'mrkdwn', 'text': '*SyzScope:*\n{}'.format(data['syzscope'])}
        block.append(syzscope_section)
        
        return block
    
    def post_message(self, block):
        try:
            self.client.chat_postMessage(
                channel=self.conversation_id,
                text="New bug reproducable on downstream distros",
                blocks=block
            )
            self.logger.info("Post new message to channel")
        except SlackApiError as e:
            self.logger.error("Failed to post message to channel: {}".format(e))
        return
    
    def generate_report(self):
        final_report = "\n".join(self.report)
        self.logger.info(final_report)
        self._write_to(final_report, self.REPORT_NAME)
    
    def _write_to(self, content, name):
        file_path = "{}/{}".format(self.path_case_plugin, name)
        super()._write_to(content, file_path)

