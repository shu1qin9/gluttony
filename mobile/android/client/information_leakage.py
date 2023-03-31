# -*- coding: utf-8 -*-
"""
用于检测android客户端信息泄露漏洞
"""

import re
import time
import subprocess
from datetime import datetime, timedelta
from lib.core.base.logger import log_handler
from lib.core.init.console import Console
from lib.core.base.exploits import Exploits


class information_leakage(Exploits):

    def __init__(self, package_name):
        super().__init__(package_name)
        self.log = log_handler()
        self.package_name = package_name
        self.vulnerability = {
            "type": "android",
            "name": "android 客户端信息泄露漏洞",  # 漏洞名称
            "create_time": "2023-03-31",  # 漏洞创建时间
            "rank": "IL",  # 漏洞效果
            "desc": "android 客户端拒绝服务漏洞",  # 漏洞描述
            "attack": False,  # 是否存在exp
            "vulnerable": False  # 是否利用成功
        }
        self.console = Console()

    def _verify(self):
        pass


# 三种方式获取uri信息
class GetUri:

    def __init__(self):
        self.log = log_handler()

    # 动态frida hook方式获取
    def frida_get_uri(self):
        pass

    # 静态扫描Java代码方式获取
    def decompile_get_uri(self):
        pass

    # 使用android shell的方式获取
    def am_get_uri(self):
        pass


