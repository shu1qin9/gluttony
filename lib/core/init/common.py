# -*- coding: utf-8 -*-
"""
信息展示
"""
import sys
from lib.core.base import variable
from exploits.run import ExploitRun
from lib.core.init.console import Console
from lib.core.base.logger import log_handler
from exploits.init import get_exploits_list, search_exploits


class Common:
    def __init__(self):
        # 初始化信息
        self.console = Console()
        self.run = ExploitRun()
        # 漏扫默认使用验证模式
        self.attack = False
        self.log = log_handler()

    def scan_console(self, parser):
        # 数据初始化
        args = parser.parse_args()
        # 获取解析器内容
        if args.command == "scan":
            target_list, exp_module_list = self.scan_settings(args)
            if target_list:
                self.vuln_scan(target_list, exp_module_list)
            else:
                self.console.print("[bold red]未检测到攻击目标，请查看说明文档")
                parser.print_help()
        elif args.command == "mobile":
            package_name, mobile_module_list = self.mobile_settings(args)
            if package_name:
                self.mobile_scan(package_name, mobile_module_list)
            else:
                self.console.print("[bold red]未检测到扫描目标，请查看说明文档")
                parser.print_help()
        elif args.command == "exploits":
            self.show_exploits()
            sys.exit()
        else:
            parser.print_help()

    # 常规扫描的变量判断
    def scan_settings(self, args):
        # 初始化常规漏扫参数
        target_list = []
        scan_exp_path = "exploits"
        variable.set_arg("default_thread", 30)
        variable.set_arg("default_dnslog", False)
        exp_module_list = get_exploits_list(scan_exp_path)
        if args.thread:
            variable.set_arg("default_thread", args.thread)
        if args.dnslog:
            variable.set_arg("default_dnslog", True)
        if args.attack:
            self.attack = True
        if args.vuln_exploits:
            # 展示漏洞列表，并退出程序
            self.console.show_exploits(exp_module_list)
            sys.exit()
        if args.module:
            exp_module_list = search_exploits(scan_exp_path, args.module.split(","))
        if args.url and args.file is None:
            target_list.append(args.url)
        elif args.file and args.url is None:
            for target in open(args.file, 'r').readlines():
                target_list.append(target)
        return target_list, exp_module_list

    def mobile_settings(self, args):
        # 初始化攻击目标
        mobile_exp_path = "mobile"
        target_list = []
        mobile_module_list = get_exploits_list(mobile_exp_path)
        if args.packagename:
            target_list.append(args.packagename)
        if args.ipa_name:
            target_list.append(args.ipa_name)
        if args.mobile_exploits:
            # 展示漏洞列表，并退出程序
            self.console.show_exploits(mobile_module_list)
            sys.exit()
        if args.mobile_module:
            # 给出一个文件，对文件做处理
            self.log.info("此处开始处理移动文件")
        if args.mobile_file:
            mobile_module_list = search_exploits(mobile_exp_path, args.module.split(","))
        return target_list, mobile_module_list

    # 漏洞扫描
    def vuln_scan(self, target_list, exp_module_list):
        # 初始化信息展示
        self.console.print("检测到 {} 个攻击目标".format(len(target_list)))
        self.console.show_exploits(exp_module_list)
        # 漏洞验证
        if self.run.verify(target_list, exp_module_list):
            # 判断用户是否选择进行攻击模块
            if self.attack:
                self.console.print("选择使用攻击模块，加载exp")
                if self.run.attack(target_list[0], exp_module_list[0]):
                    self.console.print("漏洞利用成功")
                else:
                    self.console.print("漏洞利用失败")
        else:
            self.console.info("程序异常终止")
            sys.exit()

    def mobile_scan(self, package_name, mobile_module_list):
        # 初始化信息展示
        self.console.print("检测到 {} 个目标".format(len(package_name)))
        self.console.show_exploits(mobile_module_list)
        # 漏洞验证
        if self.run.verify(package_name, mobile_module_list):
            # 判断用户是否选择进行攻击模块
            if self.attack:
                self.console.print("选择使用攻击模块，加载exp")
                if self.run.attack(package_name[0], mobile_module_list[0]):
                    self.console.print("漏洞利用成功")
                else:
                    self.console.print("漏洞利用失败")
        else:
            self.console.info("程序异常终止")
            sys.exit()

    def show_exploits(self):
        # 初始化信息展示
        scan_exp_path = "exploits"
        mobile_exp_path = "mobile"
        exp_module_list = get_exploits_list(scan_exp_path)
        mobile_module_list = get_exploits_list(mobile_exp_path)
        exploits_module_list = exp_module_list + mobile_module_list
        self.console.show_exploits(exploits_module_list)

