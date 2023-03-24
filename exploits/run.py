# -*- coding: utf-8 -*-
"""
全局exploits执行
"""
import os
import queue
import concurrent.futures
from lib.core.base import variable
from lib.core.base.logger import log_handler
from lib.core.init.console import Console


# 多线程初始化
class ThreadPool:

    def __init__(self, max_thread):
        # 初始化信息
        self.log = log_handler()
        # 线程池执行类，继承自Executor，使用线程池异步执行提交的任务
        self.thread_pool = concurrent.futures.ThreadPoolExecutor(max_workers=max_thread)
        self.log.info("当前任务跑批最大线程数为：{}".format(max_thread))
        self.task_queue = queue.Queue()
        self.futures = {}

    def add_task(self, exp):
        self.task_queue.put(exp)

    def start_task(self):
        while self.task_queue.qsize() != 0:
            current_task = self.task_queue.get()
            current_exp = current_task
            future = self.thread_pool.submit(current_exp)
            self.futures[future] = ""
        return concurrent.futures.as_completed(self.futures)


class ExploitRun:

    def __init__(self):
        self.console = Console()

    # 漏洞验证模式
    def verify(self, target_list, exp_module_list):
        self.console.info("漏洞验证开始")
        try:
            default_thread = variable.get_arg("default_thread")
            thread_pool = ThreadPool(default_thread)
            for current_target in target_list:
                [thread_pool.add_task(
                    getattr(exp, os.path.splitext(os.path.basename(exp.__file__))[0])(current_target)._verify) for exp
                 in exp_module_list]  # 向线程池中添加所有poc和当前的url
            futures = thread_pool.start_task()
            self.console.show_result(futures)
            return True
        except Exception:
            self.console.error("多线程运行出错")
            return False

    # 漏洞攻击模式
    def attack(self, target, exp_module):
        try:
            self.console.info("开始攻击模式验证漏洞")
            if getattr(exp_module, os.path.splitext(os.path.basename(exp_module.__file__))[0])(target)._attack():
                return True
            else:
                return False
        except Exception:
            return False
