# -*- coding: utf-8 -*-
"""
对android客户端代码扫描初始化
"""

from config.config import Config
from mobile.lib.base.sast_engine import scan
from lib.core.base.logger import log_handler
from lib.core.error.exception import CodeScanException


def android_code_scan():
    # 数据初始化
    log = log_handler()

    pass