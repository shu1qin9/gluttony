# -*- coding: utf-8 -*-
"""
自定义错误抛出
"""


# 自定义漏扫错误抛出
class ExpliotException(Exception):

    def __init__(self, name, reason):
        self.name = name
        self.reason = reason


# 自定义系统函数出错的错误抛出
class SystemException(Exception):

    def __init__(self, name, reason):
        self.name = name
        self.reason = reason

