from rich.live import Live
from rich.table import Table
from rich.layout import Layout
from rich.console import Console

from syzmorph.infra.console.message import ConsoleMessage
from .routine import Routine

from multiprocessing import Manager

import time
import threading

class Interface:
    def __init__(self, title, pm, queue):
        self.pm = int(pm)
        self.routine_list = []
        self.deployer_cache = []
        self.communi_queue = queue
        self.deployers = {}
        self.console = Console()
        self.title = title
        self._init_table(title)
        for _ in range(0, self.pm):
            self.deployer_cache.append(None)
    
    def _init_layout(self):
        self.layout = Layout()
        self.layout.add_layout(self.table)
    
    def _init_table(self, title):
        self.table = Table(title=title)
        self.table.add_column("Process", justify="left", style="cyan")
        self.table.add_column("Case", justify="left", style="green")

        if self.routine_list != []:
            for module_name in self.routine_list:
                self.add_routine(module_name)
            self.add_status()
    
    def add_routine(self, routine):
        self.table.add_column(routine, justify="left", style="blue")
    
    def add_status(self):
        self.table.add_column("Status", justify="left", style="red")
    
    def update_table(self, msg: ConsoleMessage):
        res = [str(msg['proc_index']), msg['hash_val']]
        for module_name in self.routine_list:
            if module_name in msg['module']:
                [status, text, status] = msg['module'][module_name]
                text = text + ' ' + status
                res.append(text)
            else:
                res.append('')
            #res.append(module.NAME)
        res.append('')

        self.table.add_row(*res)
        return

    def update_case(self, msg):
        if msg == None:
            return
        
        self.update_table(msg)
    
    def update(self, msg: dict):
        self.deployer_cache[msg['proc_index']] = msg
        self._init_table(self.title)
        for i in range(0, self.pm):
            self.update_case(self.deployer_cache[i])
        return self.table

    
    def add_deployer(self, index, deployer):
        if index in self.deployers:
            self.err_msg("[Console] Thread {} already exists, will overwrite this deployer".format(index))
        self.deployers[index] = deployer

    def remove_deployer(self, index):
        if index not in self.deployers:
            self.err_msg("[Console] Thread {} not exists".format(index))
        if index in self.deployers:
            del self.deployers[index]
    
    def msg_dispatch(self):
        msg = self.communi_queue.get(block=True)
        print("Receive at console: {}".format(msg))
        if msg['type'] == ConsoleMessage.PLUGINS_ORDER:
            self.routine_list = msg['message']
            self._init_table(self.title)
        if msg['type'] == ConsoleMessage.INFO:
            self.update(msg)
        return self.table

    def run(self):

        self.console.clear()
        with Live(self.table, console=self.console, refresh_per_second=4) as live:
            while True:
                live.update(self.msg_dispatch(), refresh=True)
                time.sleep(1)
