# -*- coding: utf-8 -*-
"""
控制台信息
"""
import os
import platform
from pyfiglet import Figlet
from rich.table import Table
from rich.progress import track
from config.config import Config
from lib.core.base.logger import log_handler
from rich.console import Console as RichConsole
from lib.core.error.exception import ExpliotException


# 重构控制台输出以及console log打印
class Console:

    def __init__(self):
        self.config = Config()
        self.log = log_handler()
        self.console = RichConsole(color_system='256', style=None)
        self._table = Table(show_header=True, header_style="bold magenta")

    # 共有模块，用于控制台输出，以及log打印
    def print(self, desc):
        self.console.print(desc)

    def input(self, desc):
        input_text = self.console.input(desc)
        return input_text

    # 通过rich绘制table
    def table(self, records_list):
        for heading in records_list[0]:
            self._table.add_column(f"{heading}")
        for row in records_list[1::1]:
            self._table.add_row(*row)
        return self._table

    def info(self, desc):
        self.console.log(desc)

    def error(self, desc):
        self.console.log(desc)
        self.console.print_exception(show_locals=True)

    # 用于控制台展示固定信息

    # 用于展示help信息
    def usage(self):
        self.console.print(
            """
            usage：python3 main.py [-u | --url] [-f | --file] [-m | --module] [-t | --thread]
                                   [--exploits] [--attack] [--dnslog]
                                   [<args>]

            下方是各种情况下常用的扫描器命令：

            获取模块信息：      python3 main.py --exploits
            单个目标检测：      python3 main.py -u https://x.x.x.x
            批量目标检测：      python3 main.py -f url.txt
            指定攻击模块：      python3 main.py -u https://x.x.x.x -m "指定exp文件"
            使用攻击模式：      python3 main.py -u https://x.x.x.x -m "指定exp文件" --attack

            扫描参数：
                    -u / --url      测试单条目标url
                    -f / --file     测试多个目标url集合
                    -m / --module   手动指定某个攻击模块   
                    -t / --thread   指定并发线程池数量
                    --exploits      展示当前库中所有的攻击模块
                    --attack        使用脚本中的攻击模式
                    --dnslog        使用dnslog平台进行盲注   
            """
        )

    # 用于展示扫描器banner
    def show_banner(self):
        version = self.config.read_ini("GLUTTONY", "VERSION")
        update = self.config.read_ini("GLUTTONY", "UPDATE")
        self.print(Figlet(font="slant", width=200).renderText("Shui‘Scan"))
        self.print("\t\t\t\t\t[bold yellow]Shui’Scan {}".format(version))
        self.print("\t\t\t\t\t[bold yellow]Update with {}".format(update))
        self.print("\t\t\t\t\t\t\t[bold red]By Shui")

    # 用于展示exploits
    def show_exploits(self, exp_module_list):
        exp_info_list = []
        exp_num = 0
        table_info = [
            ["name", "type", "script", "attach"]
        ]
        for module in exp_module_list:
            path = module.__file__
            exp_base_name = os.path.basename(path)
            # 使用getattr获取exp列表
            try:
                module_clazz = getattr(module, os.path.splitext(exp_base_name)[0])
                # 直接读取__init__初始化参数
                result = module_clazz("http://127.0.0.1")
                vulnerability = result.vulnerability
            except Exception:
                self.error("加载exp列表失败")
                raise ExpliotException("LoadERROR", "加载exp列表失败")
            # 判断是否存在攻击模块
            attack = vulnerability.get("attack")
            if attack is None or attack is False:
                attack = ""
            else:
                exp_num += 1
            exp_info = (vulnerability.get("name"), vulnerability.get("type"), path, attack)
            exp_info_list.append(exp_info)

        for (name, vuln_type, path, attack) in exp_info_list:
            if 'Windows' in platform.system():
                table_info.append([name, vuln_type, path.split('\\')[-1], str(attack)])
            else:
                table_info.append([name, vuln_type, path.split('/')[-1], str(attack)])
        for exp in track(exp_info_list, description="正在初始化模块库...."):
            # 此处置为track展示的进度条，不做其他处理
            self.log.info("漏洞进度条加载")
        self.info("项目总计 poc：{0}, exp：{1}".format(len(exp_info_list), exp_num))
        self.print(self.table(table_info))

    # 用于展示验证模式下的结果
    def show_result(self, futures):
        for future in futures:
            try:
                # 获取多线程运行结果
                result = future.result()
                if result['vulnerable']:
                    self.info("[!] {0} 检测完成，初步探测可被攻击，poc执行结果：{1}".format(result.get("name"),
                                                                                         result.get("result")))
                else:
                    self.info("[!] {0} 检测完成，该漏洞无法利用".format(result.get("name")))
            except:
                self.error("exp利用时发生错误")
                raise ExpliotException("ExpERROR", "漏洞利用发生错误")
        self.print("[bold red]所有任务扫描完成")