# -*- coding: utf-8 -*-
"""
程序统一初始化点
"""

import os
from lib.core.base import variable


# 框架整体数据初始化
def frame_init():
    # 用于初始化全局配置文件
    variable.init()
    variable.set_arg("default_thread", 30)
    variable.set_arg("root_path", os.path.abspath("."))
