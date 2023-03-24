# -*- coding: utf-8 -*-
"""
用于检测Android客户端拒绝访问漏洞
"""
import re
import time
import subprocess
from datetime import datetime, timedelta
from lib.core.base.logger import log_handler
from lib.core.init.console import Console
from lib.core.base.exploits import Exploits


class refused_service(Exploits):

    def __init__(self, package_name):
        super().__init__(package_name)
        self.log = log_handler()
        self.package_name = package_name
        self.vulnerability = {
            "type": "android",
            "name": "android 客户端拒绝服务漏洞",  # 漏洞名称
            "create_time": "2023-03-21",  # 漏洞创建时间
            "rank": "refused",  # 漏洞效果
            "desc": "android 客户端拒绝服务漏洞",  # 漏洞描述
            "attack": False,  # 是否存在exp
            "vulnerable": False  # 是否利用成功
        }
        self.console = Console()

    def _verify(self):
        # 初始化参数
        refused_activity = []
        activity_list = self.get_activity_list(self.package_name)
        self.log.info("当前所有的Activity为：{} 个，分别为：{}".format(len(activity_list), activity_list))
        # 执行命令并记录结果
        for activity in activity_list:
            if self.check_refused_service(self.package_name, activity):
                refused_activity.append(activity)
        if refused_activity:
            self.vulnerability["vulnerable"] = True
            self.vulnerability["result"] = refused_activity
        return self.vulnerability

    # 获取Activity列表
    def get_activity_list(self, package_name):
        # 使用pm获取Activity列表
        cmd = 'adb shell pm dump {} | grep "class"'.format(package_name)
        p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = p.communicate()
        # 匹配class信息
        pattern = r'class=([^\s]+)'
        self.log.info("开始通过pm dump 获取Activity列表")
        class_list = re.findall(pattern, stdout.decode())
        activity_list = list(set(class_list))
        return activity_list

    # 检测Activity是否存在漏洞
    def check_refused_service(self, package_name, activity):
        # 数据初始化
        # 拼接Activity
        run_activity = "{0}/{1}".format(package_name, activity)
        # 获取当前时间
        now = datetime.now()
        # 往后推5秒钟
        five_seconds_ago = now + timedelta(seconds=10)
        # 转换成时间戳
        start_time = time.mktime(now.timetuple())
        end_time = time.mktime(five_seconds_ago.timetuple())
        # 命令拼接
        start_activity_cmd = "adb shell am start -n {0}".format(run_activity)
        cat_logcat_cmd = ['adb', 'logcat', '-b', 'system', '-v', 'brief', '-d', '-T', str(start_time), str(end_time),
                          '-s', 'ActivityTaskManager']
        # 正则匹配拒绝服务日志
        pattern = r'Force finishing activity {}/{}'.format(re.escape(package_name),
                                                           re.escape(activity.split(package_name)[-1]))
        try:
            # 启动Activity
            p = subprocess.Popen(start_activity_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = p.communicate()
            # 启动任意一个Activity之后，都沉睡三秒
            time.sleep(3)
            # 查看logcat日志
            logcat = subprocess.check_output(cat_logcat_cmd, universal_newlines=True)
            match = re.search(pattern, logcat)
            if match:
                self.log.info("当前 {} 存在拒绝服务漏洞".format(activity))
                return True
        except IndexError:
            self.log.exception("match匹配数据失败")
        except ValueError:
            self.log.exception("时间戳生成失败")
