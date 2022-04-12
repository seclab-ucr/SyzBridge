import os, sys, re, psutil
import logging, json
from secrets import choice

from commands import Command
from modules.vm import VM
from infra.config.vendor import Vendor
from infra.tool_box import regx_match, regx_get, init_logger

class ImageCommand(Command):
    def __init__(self):
        super().__init__()
        self.args = None
        self.ssh_user = 'root'
        self.ssh_port = None
        self.ssh_key = None
        self.build_dir = None
        self.image = None
        self.distro = None
        self.code_name = None
        self.version_since = None
        self.version_until = None
        self.commit = None
        self.cfg = None
        self.logger = None
        self.kernel_version = None
        self.kernel_package_version = None

    def add_arguments(self, parser):
        super().add_arguments(parser)

        # mandatory options
        parser.add_argument('--distro', nargs='+', action='store', choices=['ubuntu', 'fedora', 'debian'],
                            help='build ubuntu image')   
        parser.add_argument('--build-dir', nargs='+', action='store',
                            help='work dir for image build (mandatory)')
        parser.add_argument('--image', nargs='+', action='store',
                            help='distro image path (mandatory)')
        parser.add_argument('--ssh-port', nargs='+', action='store',
                            help='ssh port for distro image')
        parser.add_argument('--ssh-key', nargs='+', action='store',
                            help='ssh key for distro image')
        parser.add_argument('--ssh-user', nargs='+', action='store', default='root',
                            help='ssh key for distro image')
        
        # optional options
        parser.add_argument('--write-config', nargs='?', action='store',
                            help='Write complete image info to config file')

        # image building options
        parser.add_argument('--code-name', nargs='+', action='store',
                            help='distro code name')
        parser.add_argument('--version-since', nargs='?', action='store', default='',
                            help='pick the first distro kernel version since a date')
        parser.add_argument('--version-until', nargs='?', action='store', default='',
                            help='pick the first distro kernel version until a date')
        parser.add_argument('--commit', nargs='?', action='store', default='',
                            help='Use the specific kernel commit')

    def custom_subparser(self, parser, cmd):
        return parser.add_parser(cmd, help='Build distro image [ubuntu|fedora|debian]')

    def run(self, args):
        self.args = args
        self.check_options()
        self.logger.info("Build image for {}".format(self.distro))
        self.build_vendor_cfg()
        if not self.build_distro_image():
            return
        self.write2config()
    
    def build_vendor_cfg(self):
        cfg = {}
        cfg['distro_image'] = self.image
        cfg['ssh_key'] = self.ssh_key
        cfg['ssh_port'] = self.ssh_port
        cfg['root_user'] = self.ssh_user
        cfg['distro_code_name'] = self.code_name
        cfg['distro_name'] = self.distro
        cfg['type'] = 'distro'
        self.cfg = Vendor(cfg)

    def write2config(self):
        config = self.args.write_config
        if config == None:
            return
        try:
            cfg = json.load(open(config, 'r'))
        except:
            cfg = {}
        if 'kernel' not in cfg:
            cfg['kernel'] = {}
        cfg['kernel'][self.distro] = self.cfg
        json.dump(cfg, open(config, 'w'), indent=4)

    def check_options(self):
        self.ssh_port = int(self.args.ssh_port[0])
        self.ssh_key = self.args.ssh_key[0]
        self.build_dir = self.args.build_dir[0]
        self.distro = self.args.distro[0]
        self.image = self.args.image[0]
        self.code_name = self.args.code_name[0]
        self.version_since = self.args.version_since
        self.version_until = self.args.version_until
        self.commit = self.args.commit
        if self.args.ssh_user != None:
            self.ssh_user = self.args.ssh_user[0]
        self.logger = init_logger(logger_id=os.path.join(self.build_dir, "build.log") ,debug=True, propagate=False)
    
    def get_mem_free(self):
        with open('/proc/meminfo') as f:
            meminfo = f.read()
        matched = re.search(r'MemFree:\s+(\d+)', meminfo)
        if matched: 
            mem_free_GB = int(matched.groups()[0]) / 1024 / 1024
            return mem_free_GB
        return 0
    
    def get_cpu_count(self):
        return psutil.cpu_count()

    def build_distro_image(self):
        mem = self.get_mem_free()
        if mem == 0:
            self.logger.error("Building image requires at least 2GB of RAM")
            exit(0)
        else:
            if mem / 2 < 2:
                mem = str(2)+"G"
            elif mem / 2 > 8:
                mem = str(8)+"G"
            else:
                mem = str(int(mem / 2))+"G"
        
        cpu = self.get_cpu_count()
        if cpu > 1:
            cpu = str(int(cpu / 2))

        vm = VM(linux=None, cfg=self.cfg, hash_tag="building {}".format(self.distro), work_path=self.build_dir, 
            log_name='vm.log', logger=self.logger, debug=True,
            port=self.ssh_port, key=self.ssh_key, image=self.image, mem=mem, cpu=cpu)

        _, q = vm.run(alternative_func=self._deploy_image)
        t = q.get(block=True)
        vm.kill_vm()
        if not t:
            self.logger.error("Image build failed, check the log")
            return False
        
        _, q = vm.run(alternative_func=self._check_kernel_version)
        t = q.get(block=True)
        if not t:
            self.logger.error("Kernel version does not match {}, check grub".format(self.kernel_version))
            return False
        return True
    
    def _check_kernel_version(self, qemu: VM):
        out = qemu.command(user=self.ssh_user, cmds="uname -r", wait=True)
        for line in out:
            if line == self.kernel_version:
                qemu.alternative_func_output.put(True)
                return
        qemu.alternative_func_output.put(False)
        return
    
    def _deploy_image(self, qemu: VM):
        proj_path = os.path.join(os.getcwd(), "syzmorph")
        image_building_script = "deploy-{}-image.sh".format(self.distro)
        image_building_script_path = os.path.join(proj_path, "scripts/{}".format(image_building_script))
        dkms_path_path = os.path.join(proj_path, "resources/dkms.patch")

        ret = qemu.upload(user=self.ssh_user, src=[image_building_script_path, dkms_path_path], dst='~', wait=True)
        if ret == None or ret != 0:
            qemu.logger.error("Failed to upload {}".format(image_building_script_path))
            qemu.kill_vm()
            qemu.alternative_func_output.put(False)
            return

        qemu.command(user=self.ssh_user, cmds="chmod +x {0} && ./{0} {1} '{2}' '{3}'".format(image_building_script, 
            self.code_name, self.version_since, self.version_until, self.commit), wait=True)

        out = qemu.command(user=self.ssh_user, cmds="cd ubuntu-{} && ls -l *.ddeb".format(self.code_name), wait=True)
        
        had_ddeb = False
        ddeb_regx = r'(linux-image-(.+)-dbgsym_(.+)_amd64\.ddeb)'
        for line in out:
            if regx_match(ddeb_regx, line):
                had_ddeb = True
                ddeb_pacage = regx_get(ddeb_regx, line, 0)
                self.kernel_version = regx_get(ddeb_regx, line, 1)
                self.kernel_package_version = regx_get(ddeb_regx, line, 2)
                qemu.download(user=self.ssh_user, src=["~/ubuntu-{}/{}".format(self.code_name, ddeb_pacage)], dst=self.build_dir, wait=True)

        if not had_ddeb:
            qemu.logger.error("Failed to build image, check the log")
            qemu.kill_vm()
            qemu.alternative_func_output.put(False)
            return
        qemu.download(user=self.ssh_user, src=["/boot/grub/grub.cfg"], dst=self.build_dir, wait=True)

        if os.path.exists(os.path.join(self.build_dir, "grub.cfg")):
            grub_str = self.grub_order(os.path.join(self.build_dir, "grub.cfg"))
            if grub_str != None:
                qemu.command(user=self.ssh_user, cmds="sed -i 's/GRUB_DEFAULT=.*/GRUB_DEFAULT=\"{}\"/' /etc/default/grub && update-grub && shutdown -h now".format(grub_str), wait=True)
        #qemu.kill_vm()
        qemu.alternative_func_output.put(True)
        return
    
    def grub_order(self, grub_path):
        with open(grub_path, 'r') as f:
            texts = f.readlines()
            trees, _ = self._generate_tree(texts)
            grub_str = self._find_leaf(trees, self.kernel_version, "")
        if grub_str == None:
            self.logger.error("Failed to find grub.cfg")
            return None
        return grub_str[1:]
    
    def _find_leaf(self, tree, version, grub_str):
        for i in range(0, len(tree)):
            if type(tree[i]) == dict:
                if tree[i]['kernel'] == version:
                    grub_str += ">{}".format(i)
                    return grub_str
            if type(tree[i]) == list:
                leaf = self._find_leaf(tree[i], version, ">{}".format(i) + grub_str)
                if leaf != None:
                    return leaf
        return None

    def _generate_tree(self, text):
        first_entry = False
        tree = []
        i = 0
        bracket = 0
        menu_regx = r'^(\t+)?menuentry \'(.+)\''
        kernel_regx = r'linux\t\/vmlinuz-([0-9\.\-a-zA-Z]+)'
        while i < len(text):
            line = text[i]
            if regx_match(menu_regx, line):
                if not first_entry:
                    bracket = 0
                    first_entry = True
                bracket += 1
                tree.append({'name': regx_get(menu_regx, line, 1)})
            if not first_entry:
                i += 1
                continue
            if regx_match(r'^((\t)+)?}', line):
                bracket -= 1
                if bracket < 0:
                    return tree, i
            if regx_match(kernel_regx, line):
                tree[-1]['kernel'] = regx_get(kernel_regx, line, 0)
            if 'submenu' in line:
                t, k = self._generate_tree(text[i+1:])
                tree.append(t)
                i += k + 1
            i += 1
        return tree, len(text)