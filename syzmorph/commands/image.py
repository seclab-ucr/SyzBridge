import os, sys, re, psutil
import shutil
import time, json
from secrets import choice

from commands import Command
from modules.vm import VM
from infra.config.vendor import Vendor
from subprocess import call
from infra.tool_box import STREAM_HANDLER, regx_match, regx_get, init_logger

class ImageCommand(Command):
    FEATURE_KASAN = 1 << 0
    FEATURE_UBSAN = 1 << 1
    FEATURE_FAULT_INJECTION = 1 << 2

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
        self.get = None
        self.cfg = None
        self.logger = None
        self.kernel_version = None
        self.kernel_package_version = None
        self.enable_feature = 0

    def add_arguments(self, parser):
        super().add_arguments(parser)

        # mandatory options
        parser.add_argument('--distro', nargs='+', action='store', choices=['ubuntu', 'fedora', 'debian'],
                            help='build distro image')   
        parser.add_argument('--build-dir', nargs='+', action='store',
                            help='work dir for image build (mandatory)')
        parser.add_argument('--image', nargs='+', action='store',
                            help='distro image path (mandatory)')
        parser.add_argument('--ssh-port', nargs='+', action='store',
                            help='ssh port for distro image')
        parser.add_argument('--ssh-key', nargs='+', action='store',
                            help='ssh key for distro image')
        parser.add_argument('--ssh-user', nargs='?', action='store', default='root',
                            help='ssh key for distro image')
        
        # optional options
        parser.add_argument('--write-config', nargs='?', action='store',
                            help='Write complete image info to config file')
        parser.add_argument('--enable-kasan', action='store_true',
                            help='Enable CONFIG_KASAN')
        parser.add_argument('--enable-ubsan', action='store_true',
                            help='Enable CONFIG_UBSAN (Fall 2020)')
        parser.add_argument('--enable-fault-injection', action='store_true',
                            help='Enable CONFIG_FAULT_INJECTION')

        # image building options
        parser.add_argument('--version-since', nargs='?', action='store', default='',
                            help='[Ubuntu] pick the first distro kernel version since a date')
        parser.add_argument('--version-until', nargs='?', action='store', default='',
                            help='[Ubuntu] pick the first distro kernel version until a date')
        parser.add_argument('--get', nargs='?', action='store', default='',
                            help='[Ubuntu] Use a specific kernel commit\n'
                            '[Debian] Use a url to a .dsc file (http://snapshot.debian.org/package/linux/)\n'
                            '[Fedora] Use a specfic commit')

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
        self.logger.info("Image {}-{} is ready at {}".format(self.distro, self.kernel_version, self.build_dir))
        return
    
    def build_vendor_cfg(self):
        cfg = {}
        cfg['distro_image'] = self.image
        cfg['ssh_key'] = self.ssh_key
        cfg['ssh_port'] = self.ssh_port
        cfg['root_user'] = self.ssh_user
        cfg['distro_code_name'] = "unknown"
        cfg['distro_version'] = "unknown"
        cfg['distro_name'] = self.distro
        cfg['type'] = 'distro'
        print("[distro_image]: {}".format(self.image))
        print("[distro_name]: {}".format(self.distro))
        print("[ssh_key]: {}".format(self.ssh_key))
        print("[ssh_port]: {}".format(self.ssh_port))
        print("[root_user]: {}".format(self.ssh_user))
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
        distro_cfg = {}
        distro_cfg['distro_image'] = self.cfg.distro_image
        distro_cfg['distro_src'] = os.path.join(self.build_dir, "ubuntu-{}".format(self.code_name))
        distro_cfg['distro_name'] = self.cfg.distro_name
        distro_cfg['distro_code_name'] = self.code_name
        distro_cfg['distro_version'] = self.kernel_package_version
        distro_cfg['ssh_key'] = self.cfg.ssh_key
        distro_cfg['ssh_port'] = self.cfg.ssh_port
        distro_cfg['type'] = self.cfg.type
        distro_cfg['root_user'] = self.cfg.root_user
        distro_cfg['normal_user'] = 'syzmorph'
        cfg['kernel']["{}-{}".format(self.distro, self.kernel_package_version)] = distro_cfg

        json.dump(cfg, open(config, 'w'), indent=4)

    def check_options(self):
        self.ssh_port = int(self.args.ssh_port[0])
        self.ssh_key = self.args.ssh_key[0]
        self.build_dir = self.args.build_dir[0]
        self.distro = self.args.distro[0]
        self.image = self.args.image[0]
        self.version_since = self.args.version_since
        self.version_until = self.args.version_until
        self.get = self.args.get
        if self.args.ssh_user != None:
            self.ssh_user = self.args.ssh_user
        if self.args.enable_kasan:
            self.enable_feature |= self.FEATURE_KASAN
        if self.args.enable_ubsan:
            self.enable_feature |= self.FEATURE_UBSAN
        if self.args.enable_fault_injection:
            self.enable_feature |= self.FEATURE_FAULT_INJECTION
        self.logger = init_logger(logger_id=os.path.join(self.build_dir, "build.log") ,debug=True, propagate=False, handler_type=STREAM_HANDLER)
    
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
            time.sleep(10)
            return False
        
        time.sleep(3)
        _, q = vm.run(alternative_func=self._check_kernel_version)
        t = q.get(block=True)
        vm.kill_vm()
        if not t:
            self.logger.error("Kernel version does not match {}, check grub".format(self.kernel_version))
            time.sleep(3)
            return False
        
        if os.path.exists(os.path.join(self.build_dir, "{}.tar.gz".format(self.distro))):
            src = os.path.join(self.build_dir, "{}.tar.gz".format(self.distro))
            dst = os.path.join(self.build_dir, "{}-{}".format(self.distro, self.code_name))
            os.makedirs(dst)
            shutil.move(src, dst)
            call(args=['tar', 'xf', './{}.tar.gz'.format(self.distro)], cwd=dst)
            os.remove(os.path.join(dst, './{}.tar.gz'.format(self.distro)))

        time.sleep(10)
        return True
    
    def _check_kernel_version(self, qemu: VM):
        out = qemu.command(user=self.ssh_user, cmds="uname -r", wait=True)
        for line in out:
            if line == self.kernel_version:
                passed_check = False
                if self.enable_feature & self.FEATURE_KASAN != 0:
                    if self._kernel_config_pre_check(qemu, 'CONFIG_KASAN=y'):
                        passed_check = True
                    else:
                        qemu.alternative_func_output.put(False)
                        return
                if self.enable_feature & self.FEATURE_UBSAN != 0:
                    if self._kernel_config_pre_check(qemu, 'CONFIG_UBSAN=y'):
                        passed_check = True
                    else:
                        qemu.alternative_func_output.put(False)
                        return
                if self.enable_feature & self.FEATURE_FAULT_INJECTION != 0:
                    if self._kernel_config_pre_check(qemu, 'CONFIG_FAULT_INJECTION=y'):
                        passed_check = True
                    else:
                        qemu.alternative_func_output.put(False)
                        return
                if passed_check:
                    qemu.alternative_func_output.put(True)
                    return
                else:
                    if self.enable_feature == 0:
                        qemu.alternative_func_output.put(True)
                    else:
                        qemu.alternative_func_output.put(False)
                    return
        self.logger.error("Kernel version does not match {}, check grub".format(self.kernel_version))
        qemu.alternative_func_output.put(False)
        return
    
    def _deploy_image(self, qemu: VM):
        out = qemu.command(user=self.ssh_user, cmds="lsb_release -c | awk  '{print $2}'", wait=True)
        self.code_name = out[1]

        proj_path = os.path.join(os.getcwd(), "syzmorph")
        image_building_script = "deploy-{}-image.sh".format(self.distro)
        image_building_script_path = os.path.join(proj_path, "scripts/{}".format(image_building_script))

        if self.distro == 'ubuntu':
            dkms_path_path = os.path.join(proj_path, "resources/dkms.patch")

            ret = qemu.upload(user=self.ssh_user, src=[image_building_script_path, dkms_path_path], dst='~', wait=True)
            if ret == None or ret != 0:
                qemu.logger.error("Failed to upload {}".format(image_building_script_path))
                qemu.kill_vm()
                qemu.alternative_func_output.put(False)
                return

            if self.get == '':
                qemu.command(user=self.ssh_user, cmds="chmod +x {0} && ./{0} '{1}' '{2}' {3}".format(image_building_script, 
                    self.version_since, self.version_until, self.enable_feature), wait=True)
            else:
                qemu.command(user=self.ssh_user, cmds="chmod +x {0} && ./{0} {1} {2}".format(image_building_script, self.get, self.enable_feature), wait=True)
        
            out = qemu.command(user=self.ssh_user, cmds="cd ubuntu-{} && ls -l *.ddeb".format(self.code_name), wait=True)
            had_ddeb = False
            ddeb_regx = r'(linux-image-(unsigned-)?(.+)-dbgsym_(.+)_amd64\.ddeb)'
            for line in out:
                if regx_match(ddeb_regx, line):
                    had_ddeb = True
                    ddeb_pacage = regx_get(ddeb_regx, line, 1)
                    self.kernel_version = regx_get(ddeb_regx, line, 2)
                    self.kernel_package_version = regx_get(ddeb_regx, line, 3)

            qemu.download(user=self.ssh_user, src=["/tmp/ubuntu.tar.gz"], dst=self.build_dir, wait=True)

            if not had_ddeb:
                qemu.logger.error("Failed to build image, check the log")
                qemu.kill_vm()
                qemu.alternative_func_output.put(False)
                return
            
            qemu.download(user=self.ssh_user, src=["/boot/grub/grub.cfg"], dst=self.build_dir, wait=True)
            if os.path.exists(os.path.join(self.build_dir, "grub.cfg")):
                grub_str = self.grub_order(os.path.join(self.build_dir, "grub.cfg"))
                self.logger.info("grub command: {}".format(grub_str))
                if grub_str != None:
                    qemu.command(user=self.ssh_user, cmds="sed -i 's/GRUB_DEFAULT=.*/GRUB_DEFAULT=\"{}\"/' /etc/default/grub && update-grub && shutdown -h now".format(grub_str), wait=True)
            
        if self.distro == "debian":
            ret = qemu.upload(user=self.ssh_user, src=[image_building_script_path], dst='~', wait=True)
            if ret == None or ret != 0:
                qemu.logger.error("Failed to upload {}".format(image_building_script_path))
                qemu.kill_vm()
                qemu.alternative_func_output.put(False)
                return

            # The dsc url should be like http://snapshot.debian.org/archive/debian/20190822T152536Z/pool/main/l/linux/linux_4.19.67-1.dsc
            try:
                linux_folder = self.get[::-1].split('/')[0][::-1].split('-')[0]
                self.kernel_version = linux_folder.split('_')[1]
            except:
                self.logger.error("Cannot parse this url {}, pick a .dsc file from http://snapshot.debian.org/package/linux/".format(self.get))
                qemu.kill_vm()
                qemu.alternative_func_output.put(False)
                return
            qemu.command(user=self.ssh_user, cmds="chmod +x {0} && ./{0} {1} {2} {3}".format(image_building_script, self.get, self.kernel_version, self.enable_feature), wait=True)
            if not os.path.exists(os.path.join(self.build_dir, "debian.tar.gz")) and not os.path.exists(os.path.join(self.build_dir, "debian-{}".format(self.code_name))):
                if qemu.download(user=self.ssh_user, src=["/tmp/debian.tar.gz"], dst=self.build_dir, wait=True) != 0:
                    qemu.kill_vm()
                    qemu.alternative_func_output.put(False)
                    return
                    
            qemu.download(user=self.ssh_user, src=["/boot/grub/grub.cfg"], dst=self.build_dir, wait=True)
            if os.path.exists(os.path.join(self.build_dir, "grub.cfg")):
                grub_str = self.grub_order(os.path.join(self.build_dir, "grub.cfg"))
                self.logger.info("grub command: {}".format(grub_str))
                if grub_str != None:
                    qemu.command(user=self.ssh_user, cmds="sed -i 's/GRUB_DEFAULT=.*/GRUB_DEFAULT=\"{}\"/' /etc/default/grub && update-grub && shutdown -h now".format(grub_str), wait=True)
        
        if self.distro == "fedora":
            out = qemu.command(user=self.ssh_user, cmds="uname -r", wait=True);
            self.code_name = ""
            for line in out:
                if regx_match(r"\.fc(\d+)\.x86_64", line):
                    self.code_name = regx_get(r"\.fc(\d+)\.x86_64", line, 0)
            
            if self.code_name == "":
                qemu.logger.error("Failed to get code name")
                qemu.kill_vm()
                qemu.alternative_func_output.put(False)
                return

            kernel_spec_patch_path = os.path.join(proj_path, "resources/kernel_spec.patch")

            ret = qemu.upload(user=self.ssh_user, src=[image_building_script_path, kernel_spec_patch_path], dst='~', wait=True)
            if ret == None or ret != 0:
                qemu.logger.error("Failed to upload {}".format(image_building_script_path))
                qemu.kill_vm()
                qemu.alternative_func_output.put(False)
                return

            if self.get == '':
                out = qemu.command(user=self.ssh_user, cmds="chmod +x {0} && ./{0} '{1}' '{2}' {3} {4}".format(image_building_script, 
                    self.version_since, self.version_until, self.enable_feature, self.code_name), wait=True)
            else:
                out = qemu.command(user=self.ssh_user, cmds="chmod +x {0} && ./{0} {1} {2} {3}".format(image_building_script, self.get, self.enable_feature, self.code_name), wait=True)

            for line in out:
                if line.startswith("MAGIC!!?"):
                    self.kernel_version = line.split("MAGIC!!?")[1][1:]
            
            if not os.path.exists(os.path.join(self.build_dir, "fedora.tar.gz")) and not os.path.exists(os.path.join(self.build_dir, "fedora-{}".format(self.code_name))):
                if qemu.download(user=self.ssh_user, src=["/tmp/fedora.tar.gz"], dst=self.build_dir, wait=True) != 0:
                    qemu.kill_vm()
                    qemu.alternative_func_output.put(False)
                    return

            out = qemu.command(user=self.ssh_user, cmds="ls -l /boot/vmlinuz-*".format(self.kernel_version), wait=True)
            for line in out:
                if regx_match(r'vmlinuz-(.*)\+debug', line):
                    self.kernel_version = regx_get(r'vmlinuz-(.*\+debug)', line, 0)
                    qemu.command(user=self.ssh_user, cmds="grubby --set-default /boot/vmlinuz-{}".format(self.kernel_version), wait=True);
                    qemu.command(user=self.ssh_user, cmds="grub2-mkconfig -o /boot/grub2/grub.cfg", wait=True);
                    break;

        qemu.alternative_func_output.put(True)
        return
    
    def grub_order(self, grub_path):
        with open(grub_path, 'r') as f:
            texts = f.readlines()
            trees, _ = self._generate_tree(texts)
            self.logger.debug("finding {} in grub trees:\n{}".format(self.kernel_version, trees))
            grub_str = self._find_leaf(trees, self.kernel_version, "")
        if grub_str == None:
            self.logger.error("Failed to find grub.cfg")
            return None
        return grub_str[1:]
    
    def _kernel_config_pre_check(self, qemu, config):
        out = qemu.command(cmds="grep {} /boot/config-`uname -r`".format(config), user=self.ssh_user, wait=True)
        for line in out:
            line = line.strip()
            if line == config:
                self.logger.info("{} is enabled".format(config))
                return True
        return False
    
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
        kernel_regx = r'linux\t(\/boot)?\/vmlinuz-([0-9\.\-a-zA-Z]+)'
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
                tree[-1]['kernel'] = regx_get(kernel_regx, line, 1)
            if 'submenu' in line:
                t, k = self._generate_tree(text[i+1:])
                tree.append(t)
                i += k + 1
            i += 1
        return tree, len(text)