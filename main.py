# -*- coding: utf-8 -*-
import os
import argparse
import traceback
from lib.core.base import variable
from lib.core.init.console import Console
from lib.core.init.common import Common


# 获取解析器
def create_parser():
    parser = argparse.ArgumentParser(description="一款多功能扫描器，目前包含：主动漏扫、frida hook")
    subparsers = parser.add_subparsers(dest='command')
    # 仅展示所有的漏洞
    exploits_parser = subparsers.add_parser("exploits", help="展示现有的漏洞")
    # 常规漏扫
    scan_parser = subparsers.add_parser("scan", help="扫描常规目标漏洞")
    scan_parser.add_argument("-u", "--url", type=str, help="测试单条目标url")
    scan_parser.add_argument("-f", "--file", type=str, help="测试多个目标url集合")
    scan_parser.add_argument("-mo", "--module", type=str, help="手动指定某个攻击模块")
    scan_parser.add_argument("-t", "--thread", type=int, help="指定并发线程池数量")
    scan_parser.add_argument("--vuln_exploits", action="store_true",  help="展示当前库中所有的攻击模块")
    scan_parser.add_argument("--attack", action="store_true", help="使用脚本中的攻击模式")
    scan_parser.add_argument("--dnslog", action="store_true", help="使用dnslog平台进行盲注")
    # 移动端 漏扫
    mobile_parser = subparsers.add_parser("mobile", help="扫描移动端目标漏洞")
    mobile_parser.add_argument("-p", "--packagename", type=str, help="测试单个apk的包名")
    mobile_parser.add_argument("-i", "--ipa_name", type=str, help="测试单个ipa的包名")
    mobile_parser.add_argument("-mf", "--mobile_file", type=str, help="指定测试文件包名的路劲")
    mobile_parser.add_argument("-mo", "--mobile_module", type=str, help="手动指定某个攻击模块")
    mobile_parser.add_argument("--mobile_exploits", action="store_true", help="展示当前可执行的hook操作")
    # 返回对应目标
    return parser


def main():
    # 初始化信息
    console = Console()
    # 用于初始化全局配置文件
    variable.init()
    variable.set_arg("root_path", os.path.abspath("."))
    try:
        common = Common()
        console = Console()
        console.show_banner()
        parser = create_parser()
        common.scan_console(parser)
    except Exception:
        console.error(traceback.format_exc())
        console.error("扫描程序出错")


if __name__ == '__main__':
    main()

