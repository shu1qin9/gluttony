# -*- coding: utf-8 -*-
"""
用于frida的初始化
"""

import frida
from lib.core.base.logger import log_handler
from lib.core.error.exception import SystemException


class Frida:

    def __init__(self):
        self.log = log_handler()

    # 连接frida server
    def connect(self):
        session = None
        device = None
        try:
            device = frida.get_device()
        except Exception:
            self.log.exception("frida连接失败")
            raise SystemException("FridaError", "frida连接失败")