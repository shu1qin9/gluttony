# -*- coding: utf-8 -*-
"""
读取config.ini，返回内容
"""

import json
from configparser import ConfigParser, ExtendedInterpolation


class Config(object):
    def __init__(self):
        self.conf = ConfigParser(interpolation=ExtendedInterpolation())
        self.conf.read("config/config.ini")

    def read_ini(self, section, option, isjson=False, islist=False):
        value = self.conf.get(section, option)
        if isjson:
            value = json.loads(value)
            return value
        elif islist:
            value = eval(value)
            return value
        else:
            return value
