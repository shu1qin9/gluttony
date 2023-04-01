# -*- coding: utf-8 -*-
"""
初始化扫描器
"""
import os
import platform
import importlib
from lib.core.base import variable
from config.config import Config
from lib.core.init.console import Console
from lib.core.error.exception import ExpliotException


# 遍历枚举路劲下的所有文件
def get_files_path(file_path):
    # 数据初始化
    file_list = []
    config = Config()
    if os.path.isdir(file_path):
        for check_file in os.listdir(file_path):
            current_path = os.path.join(file_path, check_file)
            exploits_black_list = config.read_ini("GLUTTONY", "BLACK_LIST", isjson=True).get("exploits")
            # 判断当前绝对路劲是否为python文件
            if (os.path.isfile(current_path) and check_file.split('.')[-1] != 'py') or any(
                    current_path.startswith(path) for path in exploits_black_list):
                continue
            each_path = get_files_path(current_path)
            # 加载黑名单
            for file in each_path:
                # 判断文件是否在黑名单，如果存在则不予记录
                if get_module_name(file) in exploits_black_list:
                    continue
                else:
                    file_list.append(file)

    else:
        file_list.append(file_path)
    return file_list


# 获取可执行exp路劲
def get_module_path(exp_path):
    if "Windows" in platform.system():
        exp_path = exp_path.lstrip('\\')
        module_path = exp_path.replace("\\", ".")
    else:
        exp_path = exp_path.lstrip('/')
        module_path = exp_path.replace("/", ".")
    module_path = module_path.replace('.py', '')
    return module_path


# 依据传入路劲获取文件名
def get_module_name(exp_path):
    if 'Windows' in platform.system():
        filename = exp_path.split('\\')[-1]
    else:
        filename = exp_path.split('/')[-1]
    return filename


# 枚举获取exploits文件夹下所有exp
def get_exploits_list(file_path):
    # 基本信息初始化
    exp_module_list = []
    root_path = variable.get_arg("root_path")
    exp_file_path = os.path.join(root_path, file_path)
    exp_path_list = get_files_path(exp_file_path)
    for exp_path in exp_path_list:
        exp_path = exp_path.replace(root_path, "")
        exp_module_path = get_module_path(exp_path)
        exp_module_list.append(importlib.import_module(exp_module_path))
    return exp_module_list


# 实现解析器--module功能
def search_exploits(file_path, module_list):
    # 数据初始化
    search = True
    console = Console()
    exp_module_list = []
    root_path = variable.get_arg("root_path")
    exp_file_path = os.path.join(root_path, file_path)
    exp_path_list = get_files_path(exp_file_path)
    # 循环遍历查询
    for module in module_list:
        for exp_path in exp_path_list:
            exp_replace_path = exp_path.replace(root_path, '')
            poc_filename = get_module_name(exp_replace_path)
            if module == poc_filename and search:
                try:
                    console.print("检索到exploits文件：{}".format(poc_filename))
                    exp_module_path = get_module_path(exp_replace_path)
                    exp_module_list.append(importlib.import_module(exp_module_path))
                    search = False
                    break
                except Exception:
                    search = True
                    console.error("未能成功找打当前模块")
                    raise ExpliotException("FindExpERROR", "未找到指定模块信息")
        if search:
            console.print("未检索到exploit文件：{}".format(module))
        search = True
    return exp_module_list
