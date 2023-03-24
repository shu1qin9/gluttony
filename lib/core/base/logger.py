# -*- coding: utf-8 -*-
"""
日志生成
:desc: 调用 logger 类的文件
"""

import time
from loguru import logger


def log_handler():
    log_time = time.strftime("%Y-%m-%d", time.localtime())
    # 日志保存位置和命名格式
    file = "./log/" + log_time + ".log"
    # 避免重复打印
    logger.remove()
    logger.add(file, backtrace=True, diagnose=True,
               format="{time:YYYY-MM-DD HH:mm:ss.SSS} - [{level}] - [{file}] - [{function}] - [line:{line}] - {message}")
    return logger