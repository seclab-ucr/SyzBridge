import os, sys, re, psutil
import shutil
import time, json
from secrets import choice

from commands import Command
from modules.vm import VM
from infra.config.vendor import Vendor
from infra.config.config import Config
from subprocess import call
from infra.tool_box import STREAM_HANDLER, FILE_HANDLER, local_command, regx_match, regx_get, init_logger

from rich.console import Group
from rich.panel import Panel
from rich.live import Live
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)

image_inspection_step_actions = ["Checking kernel version", "Checking KASAN", "Checking trace-cmd", "Check kernel source", "Check kernel modules"]
run_script_step_actions = ["Uploading script", "Running script"]
qemu_boot_progress_percentage = 40
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
        self.kernel = None
        self.logger = None
        self.kernel_version = None
        self.kernel_package_version = None
        self._step_actions = ["Booting"]
        self._each_step_progress_percentage = (100 - qemu_boot_progress_percentage)
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
        parser.add_argument('--config', nargs='?', action='store',
                            help='Check kernel image in config file')
        parser.add_argument('--check-distro', nargs='?', action='store',
                            help='Check a specific distro image in config file.\n'
                                'You can also set --check-distro to \"all\"')
        parser.add_argument('--run-script', nargs='?', action='store',
                            help='Run script on one or more distros.\n'
                                'If no --check-distro is specified, run script on all distros in config file.')
        parser.add_argument('--write-config', nargs='?', action='store',
                            help='Write complete image info to config file')
        parser.add_argument('--enable-kasan', action='store_true',
                            help='Enable CONFIG_KASAN')
        parser.add_argument('--enable-ubsan', action='store_true',
                            help='Enable CONFIG_UBSAN (Fall 2020)')
        parser.add_argument('--enable-fault-injection', action='store_true',
                            help='Enable CONFIG_FAULT_INJECTION')
        parser.add_argument('--enable-extra', action='store', nargs='+',
                            help='Enable extra config')
        parser.add_argument('--disable-extra', action='store', nargs='+',
                            help='Disable extra config')

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
        if not self.check_options():
            return
        if self.args.check_distro != None or self.args.run_script != None:
            self.inspect_kernels()
            return
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
        cfg['normal_user'] = "etenal"
        cfg['distro_code_name'] = "unknown"
        cfg['distro_version'] = "unknown"
        cfg['distro_name'] = self.distro
        cfg['type'] = 'distro'
        print("[distro_image]: {}".format(self.image))
        print("[distro_name]: {}".format(self.distro))
        print("[ssh_key]: {}".format(self.ssh_key))
        print("[ssh_port]: {}".format(self.ssh_port))
        print("[root_user]: {}".format(self.ssh_user))
        self.kernel = Vendor(cfg)

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
        distro_cfg['distro_image'] = self.kernel.distro_image
        distro_cfg['distro_src'] = os.path.join(self.build_dir, "ubuntu-{}".format(self.code_name))
        distro_cfg['distro_name'] = self.kernel.distro_name
        distro_cfg['distro_code_name'] = self.code_name
        distro_cfg['distro_version'] = self.kernel_package_version
        distro_cfg['ssh_key'] = self.kernel.ssh_key
        distro_cfg['ssh_port'] = self.kernel.ssh_port
        distro_cfg['type'] = self.kernel.type
        distro_cfg['root_user'] = self.kernel.root_user
        distro_cfg['normal_user'] = 'syzmorph'
        cfg['kernel']["{}-{}".format(self.distro, self.kernel_package_version)] = distro_cfg

        json.dump(cfg, open(config, 'w'), indent=4)

    def check_options(self):
        if self.args.check_distro != None and self.args.config == None:
            print("--check-distro must come with --config")
            return False
        if self.args.run_script != None and self.args.config == None:
            print("--run-script must come with --config")
            return False
        if self.args.config != None:
            return True
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
        return True
    
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
            elif mem / 2 >= 8:
                mem = str(int(mem / 2))+"G"
        
        cpu = self.get_cpu_count()
        if cpu > 1:
            cpu = str(int(cpu / 2))

        vm = VM(linux=None, kernel=self.kernel, hash_tag="building {}".format(self.distro), work_path=self.build_dir, 
            log_name='vm.log', logger=self.logger, debug=True,
            port=self.ssh_port, key=self.ssh_key, image=self.image, mem=mem, cpu=cpu)

        vm.run(alternative_func=self._deploy_image)
        t = vm.wait()
        vm.kill_vm()
        if not t:
            self.logger.error("Image build failed, check the log")
            time.sleep(10)
            return False
        
        dst = os.path.join(self.build_dir, "{}-{}".format(self.distro, self.code_name))
        if os.path.exists(os.path.join(self.build_dir, "{}.tar.gz".format(self.distro))):
            src = os.path.join(self.build_dir, "{}.tar.gz".format(self.distro))
            os.makedirs(dst)
            shutil.move(src, dst)
            call(args=['tar', 'xf', './{}.tar.gz'.format(self.distro)], cwd=dst)
            os.remove(os.path.join(dst, './{}.tar.gz'.format(self.distro)))
        elif not os.path.exists(dst):
            self.logger.error("Cannot find {}.tar.gz, please make sure the building is succeed".format(self.distro))
            return False

        time.sleep(3)
        vm.run(alternative_func=self._check_kernel_version)
        t = vm.wait()
        vm.kill_vm()
        if not t:
            self.logger.error("Kernel version does not match {}, check grub".format(self.kernel_version))
            time.sleep(3)
            return False
        
        dst = os.path.join(self.build_dir, "modules")
        if os.path.exists(os.path.join(self.build_dir, "modules.tar.gz")):
            src = os.path.join(self.build_dir, "modules.tar.gz")
            os.makedirs(dst)
            shutil.move(src, dst)
            call(args=['tar', 'xf', './modules.tar.gz'], cwd=dst)
            os.remove(os.path.join(dst, './modules.tar.gz'.format(self.distro)))
            if self.distro == "fedora":
                self._decompress_ko(dst)
        elif not os.path.exists(dst):
            self.logger.error("Cannot find modules.tar.gz, please make sure the building is succeed")
            return False

        return True
    
    def inspect_kernels(self):
        if self.args.run_script != None:
            self._step_actions.extend(run_script_step_actions)
        self._step_actions.extend(image_inspection_step_actions)
        self._step_actions.append("Shutdown")
        self._each_step_progress_percentage = (100 - qemu_boot_progress_percentage) / (len(self._step_actions) -1 )
        
        self.cfg = Config()
        self.cfg.load_from_file(self.args.config)
        self.logger = init_logger(logger_id=os.path.join(os.getcwd(), "image_inspection.log") ,debug=False, propagate=False, handler_type=FILE_HANDLER)
        
        if self.args.check_distro == None or self.args.check_distro == "all":
            all_distros = self.cfg.get_all_distros()
        else:
            all_distros = [self.cfg.get_distro_by_name(self.args.check_distro)]
        n_distro = len(all_distros)
        mem = self.get_mem_free()
        if mem == 0:
            self.logger.error("Building image requires at least 2GB of RAM")
            exit(0)
        else:
            if mem / n_distro < 2:
                mem = "1G"
            elif mem / n_distro >= 2:
                mem = "2G"
        
        cpu = self.get_cpu_count()
        if cpu > n_distro*2:
            cpu = "2"
        else:
            cpu = "1"
            
        self._init_progress_bar()
        
        overall_task_id = self.overall_progress.add_task("", total=n_distro)
        
        with Live(self.progress_group):
            idx = 0
            for distro in all_distros:
                work_dir = os.path.dirname(distro.distro_image)
                vm = VM(linux=None, kernel=distro, hash_tag="inspecting {}".format(distro.distro_name), work_path=work_dir, 
                    log_name='vm_inspection.log', logger=self.logger, debug=False,
                    port=distro.ssh_port, key=distro.ssh_key, image=distro.distro_image, mem=mem, cpu=cpu)
                
                top_descr = "[bold #AAAAAA](%d out of %d distros inspected)" % (idx, n_distro)
                self.overall_progress.update(overall_task_id, description=top_descr)

                # add progress bar for steps of this app, and run the steps
                current_task_id = self.current_app_progress.add_task("Insepcting distro {}".format(distro.distro_name))
                app_steps_task_id = self.app_steps_progress.add_task(
                    "", total=100, name=distro.distro_name
                )
                step_task_id = self.step_progress.add_task("", action=self._step_actions[0], name=distro.distro_name)
                vm.run(alternative_func=self._do_inspection, args=(app_steps_task_id, self.app_steps_progress, step_task_id))
                self._progress_while_booting(vm, app_steps_task_id, self.app_steps_progress)
                
                res = vm.wait()
                step_task_id = res[-1]
                self._step_progress_finish(step_task_id)
                res = res[:len(res)-1]
                self.app_steps_progress.update(app_steps_task_id, completed=100)
                while vm.instance.poll() == None:
                    time.sleep(1)
                vm.kill()
                # stop and hide steps progress bar for this specific app
                self.app_steps_progress.update(app_steps_task_id, visible=False)
                self.current_app_progress.stop_task(current_task_id)
                if res == []:
                    self.current_app_progress.update(
                        current_task_id, description="[bold green]{} PASS!".format(distro.distro_name)
                    )
                else:
                    self.current_app_progress.update(
                        current_task_id, description="[bold red]{} {}".format(distro.distro_name, " | ".join(res))
                    )

                # increase overall progress now this task is done
                self.overall_progress.update(overall_task_id, advance=1)
                idx += 1

            # final update for message on overall progress bar
            self.overall_progress.update(
                overall_task_id, description="[bold green] {} distros inspected!".format(n_distro)
            )
    
    def _step_progress_finish(self, step_task_id, idx=None):
        self.step_progress.update(step_task_id, advance=1)
        self.step_progress.stop_task(step_task_id)
        self.step_progress.update(step_task_id, visible=False)
        if idx != None:
            return idx + 1
        return None
                
    def _progress_while_booting(self, vm, job, job_progress):
        while not vm.qemu_ready:
            completed = len(vm.output)/10
            if completed > qemu_boot_progress_percentage:
                completed = qemu_boot_progress_percentage
            job_progress.update(job, completed=int(completed))
            time.sleep(1)
        return
            
    def _init_progress_bar(self):
        # progress bar for current app showing only elapsed time,
        # which will stay visible when app is installed
        self.current_app_progress = Progress(
            TimeElapsedColumn(),
            TextColumn("{task.description}"),
        )

        # progress bars for single app steps (will be hidden when step is done)
        self.step_progress = Progress(
            TextColumn("  "),
            TimeElapsedColumn(),
            TextColumn("[bold purple]{task.fields[action]}"),
            SpinnerColumn("simpleDots"),
        )
        # progress bar for current app (progress in steps)
        self.app_steps_progress = Progress(
            TextColumn(
                "[bold blue]Progress for insepcting {task.fields[name]}: {task.percentage:.0f}%"
            ),
            BarColumn()
        )
        # overall progress bar
        self.overall_progress = Progress(
            TimeElapsedColumn(), BarColumn(), TextColumn("{task.description}")
        )
        
        self.progress_group = Group(
            Panel(Group(self.current_app_progress, self.step_progress, self.app_steps_progress)),
            self.overall_progress,
        )
        
        return
            
    def _do_inspection(self, qemu: VM, job, job_progress: Progress, last_step_task_id):
        res = []
        distro = qemu.kernel
        job_progress.update(job, completed=qemu_boot_progress_percentage)
        idx_step = self._step_progress_finish(last_step_task_id, 0)
        
        if self.args.run_script != None:
            step_task_id = self.step_progress.add_task("", action=self._step_actions[idx_step], name=distro.distro_name)
            ret = qemu.upload(user=self.ssh_user, src=[self.args.run_script], dst='/tmp/myscript.sh', wait=True)
            if ret == None or ret != 0:
                qemu.logger.error("Failed to upload {}".format(self.args.run_script))
                return False
            job_progress.update(job, advance=self._each_step_progress_percentage)
            idx_step = self._step_progress_finish(step_task_id, idx_step)
            
            step_task_id = self.step_progress.add_task("", action=self._step_actions[idx_step], name=distro.distro_name)
            out = qemu.command(user=self.ssh_user, cmds="chmod +x /tmp/myscript.sh && /tmp/myscript.sh", wait=True)
            job_progress.update(job, advance=self._each_step_progress_percentage)
            idx_step = self._step_progress_finish(step_task_id, idx_step)
        
        step_task_id = self.step_progress.add_task("", action=self._step_actions[idx_step], name=distro.distro_name)
        out = qemu.command(user=self.ssh_user, cmds="uname -r", wait=True)
        
        if regx_match(r'^(\d+\.\d+\.\d+)', out[1]):
            kerenl_version = regx_get(r'^(\d+\.\d+\.\d+)', out[1], 0)
        if regx_match(r'^(\d+\.\d+\.\d+-\d+)', out[1]):
            kerenl_version = regx_get(r'^(\d+\.\d+\.\d+-\d+)', out[1], 0)
        if kerenl_version != distro.distro_version:
            res.append("Kernel Version Check Failed, {} != {}".format(out[1], distro.distro_version))
        
        job_progress.update(job, advance=self._each_step_progress_percentage)
        idx_step = self._step_progress_finish(step_task_id, idx_step)
        
        step_task_id = self.step_progress.add_task("", action=self._step_actions[idx_step], name=distro.distro_name)
        pass_kasan_check = False
        if self._kernel_config_pre_check(qemu, 'CONFIG_KASAN=y'):
            pass_kasan_check = True
        if not pass_kasan_check:
            res.append("KASAN Check Failed")
        
        job_progress.update(job, advance=self._each_step_progress_percentage)
        idx_step = self._step_progress_finish(step_task_id, idx_step)
        
        step_task_id = self.step_progress.add_task("", action=self._step_actions[idx_step], name=distro.distro_name)
        pass_trace_cmd_check = True
        out = qemu.command(user=self.ssh_user, cmds="trace-cmd", wait=True)
        for line in out:
            if "command not found" in line:
                pass_trace_cmd_check = False
        if not pass_trace_cmd_check:
            res.append("trace-cmd does not installed")
        job_progress.update(job, advance=self._each_step_progress_percentage)
        idx_step = self._step_progress_finish(step_task_id, idx_step)
        
        step_task_id = self.step_progress.add_task("", action=self._step_actions[idx_step], name=distro.distro_name)
        pass_kernel_source = False
        config_path = os.path.join(distro.distro_src, "config")
        vmlinux_path = os.path.join(distro.distro_src, "vmlinux")
        if os.path.exists(config_path) and os.path.exists(vmlinux_path):
            pass_kernel_source = True
        if not pass_kernel_source:
            res.append("{} does not contains kernel source".format(distro.distro_src))
        job_progress.update(job, advance=self._each_step_progress_percentage)
        idx_step = self._step_progress_finish(step_task_id, idx_step)
        
        step_task_id = self.step_progress.add_task("", action=self._step_actions[idx_step], name=distro.distro_name)
        base_dir = os.path.dirname(distro.distro_src)
        modules_dir = os.path.join(base_dir, "modules")
        pass_kernel_modules = os.path.exists(modules_dir)
        if not pass_kernel_modules:
            res.append("Can't find kernel modules")
        job_progress.update(job, advance=self._each_step_progress_percentage)
        idx_step = self._step_progress_finish(step_task_id, idx_step)
        
        step_task_id = self.step_progress.add_task("", action=self._step_actions[idx_step], name=distro.distro_name)
        qemu.command(user=self.ssh_user, cmds="shutdown -h now", wait=True)
        res.append(step_task_id)
        return res
    
    def _check_kernel_version(self, qemu: VM):
        out = qemu.command(user=self.ssh_user, cmds="uname -r", wait=True)
        for line in out:
            if line == self.kernel_version:
                passed_check = False
                if self.enable_feature & self.FEATURE_KASAN != 0:
                    if self._kernel_config_pre_check(qemu, 'CONFIG_KASAN=y'):
                        passed_check = True
                    else:
                        return False
                if self.enable_feature & self.FEATURE_UBSAN != 0:
                    if self._kernel_config_pre_check(qemu, 'CONFIG_UBSAN=y'):
                        passed_check = True
                    else:
                        return False
                if self.enable_feature & self.FEATURE_FAULT_INJECTION != 0:
                    if self._kernel_config_pre_check(qemu, 'CONFIG_FAULT_INJECTION=y'):
                        passed_check = True
                    else:
                        return False
                if passed_check:
                    self._retrieve_modules(qemu)
                    qemu.command(user=self.ssh_user, cmds="shutdown -h now", wait=True)
                    time.sleep(10)
                    return True
                else:
                    if self.enable_feature == 0:
                        return True
                    else:
                        return False
        self.logger.error("Kernel version does not match {}, check grub".format(self.kernel_version))
        return False
    
    def _retrieve_modules(self, qemu: VM):
        qemu.command(user=self.ssh_user, cmds="tar -czf /tmp/modules.tar.gz -C /lib/modules/`uname -r`/kernel .", wait=True)
        qemu.download(user=self.ssh_user, src=["/tmp/modules.tar.gz"], dst=os.path.join(self.build_dir, "modules.tar.gz"), wait=True)
    
    def _deploy_image(self, qemu: VM):
        out = qemu.command(user=self.ssh_user, cmds="lsb_release -c | awk  '{print $2}'", wait=True)
        self.code_name = out[1]

        proj_path = os.path.join(os.getcwd(), "syzmorph")
        image_building_script = "deploy-{}-image.sh".format(self.distro)
        image_building_script_path = os.path.join(proj_path, "scripts/{}".format(image_building_script))

        if self.args.disable_extra != None:
            disable_config_file = self.build_dir+'/disable_extra_config'
            with open(disable_config_file, 'w') as f:
                f.writelines(self.args.disable_extra)
                f.close()
                ret = qemu.upload(user=self.ssh_user, src=[disable_config_file], dst='~', wait=True)
                if ret == None or ret != 0:
                    qemu.logger.error("Failed to upload {}".format(disable_config_file))
                    return False
        
        if self.args.enable_extra != None:
            enable_config_file = self.build_dir+'/enable_extra_config'
            with open(enable_config_file, 'w') as f:
                f.writelines(self.args.enable_extra)
                f.close()
                ret = qemu.upload(user=self.ssh_user, src=[enable_config_file], dst='~', wait=True)
                if ret == None or ret != 0:
                    qemu.logger.error("Failed to upload {}".format(enable_config_file))
                    return False

        if self.distro == 'ubuntu':
            dkms_path_path = os.path.join(proj_path, "resources/dkms.patch")

            ret = qemu.upload(user=self.ssh_user, src=[image_building_script_path, dkms_path_path], dst='~', wait=True)
            if ret == None or ret != 0:
                qemu.logger.error("Failed to upload {}".format(image_building_script_path))
                return False

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
                return False
            
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
                return False

            # The dsc url should be like http://snapshot.debian.org/archive/debian/20190822T152536Z/pool/main/l/linux/linux_4.19.67-1.dsc
            try:
                linux_folder = self.get[::-1].split('/')[0][::-1].split('-')[0]
                self.kernel_version = linux_folder.split('_')[1]
            except:
                self.logger.error("Cannot parse this url {}, pick a .dsc file from http://snapshot.debian.org/package/linux/".format(self.get))
                return False
            qemu.command(user=self.ssh_user, cmds="chmod +x {0} && ./{0} {1} {2} {3}".format(image_building_script, self.get, self.kernel_version, self.enable_feature), wait=True)
            if not os.path.exists(os.path.join(self.build_dir, "debian.tar.gz")) and not os.path.exists(os.path.join(self.build_dir, "debian-{}".format(self.code_name))):
                if qemu.download(user=self.ssh_user, src=["/tmp/debian.tar.gz"], dst=self.build_dir, wait=True) != 0:
                    return False
                    
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
                return False

            kernel_spec_patch_path = os.path.join(proj_path, "resources/kernel_spec.patch")

            ret = qemu.upload(user=self.ssh_user, src=[image_building_script_path, kernel_spec_patch_path], dst='~', wait=True)
            if ret == None or ret != 0:
                qemu.logger.error("Failed to upload {}".format(image_building_script_path))
                return False

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
                    return False

            out = qemu.command(user=self.ssh_user, cmds="ls -l /boot/vmlinuz-*".format(self.kernel_version), wait=True)
            for line in out:
                if regx_match(r'vmlinuz-(.*)\+debug', line):
                    self.kernel_version = regx_get(r'vmlinuz-(.*\+debug)', line, 0)
                    qemu.command(user=self.ssh_user, cmds="grubby --set-default /boot/vmlinuz-{}".format(self.kernel_version), wait=True);
                    qemu.command(user=self.ssh_user, cmds="grub2-mkconfig -o /boot/grub2/grub.cfg", wait=True);
                    break;
            qemu.command(user=self.ssh_user, cmds="shutdown -h now", wait=True)

        time.sleep(10) # Wait for normally shutdown
        return True
    
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

    def _decompress_ko(self, module_path):
        local_command(command="xz --decompress `find ./ -name \"*.ko.xz\"`", shell=True, cwd=module_path)
        return
    
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