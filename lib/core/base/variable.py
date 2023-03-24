# -*- coding: utf-8 -*-
"""
用于存储全局变量
"""

from lib.core.error.exception import SystemException


def init():
    global _global_dict
    _global_dict = {}


def set_arg(key, value):
    _global_dict[key] = value


def get_arg(key):
    try:
        return _global_dict[key]
    except KeyError:
        raise SystemException("ParamUndefinedERROR", "参数{}未定义".format(key))