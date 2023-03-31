# -*- coding: utf-8 -*-
"""
加载libsast正则匹配引擎，用于客户端代码扫描
"""

from libsast import Scanner
from lib.core.base.logger import log_handler
from lib.core.error.exception import CodeScanException


def scan(rule, extensions, paths, ignore_paths=None):
    log = log_handler()
    try:
        options = {
            "match_rules": rule,
            "match_extensions": extensions,
            "ignore_paths": ignore_paths,
            "show_progress": False
        }
        scanner = Scanner(options, paths)
        result = scanner.scan()
        if result:
            return format_findings(result.get("pattern_matcher"), paths[0])
    except Exception:
        log.exception("libsast引擎代码扫描失败")
        raise CodeScanException("CodeScanError", "libsast引擎代码扫描失败")
    return {}


# 对扫描结果格式化处理
def format_findings(findings, root):
    for details in findings.values():
        tmp_dict = {}
        for file_meta in details["files"]:
            file_meta["file_path"] = file_meta["file_path"].replace(root, "", 1)
            file_path = file_meta["file_path"]
            start = file_meta["match_lines"][0]
            end = file_meta["match_lines"][1]
            if start == end:
                match_lines = start
            else:
                exp_lines = []
                for i in range(start, end + 1):
                    exp_lines.append(i)
                match_lines = ",".join(str(m) for m in exp_lines)
            if file_path not in tmp_dict:
                tmp_dict[file_path] = str(match_lines)
            elif tmp_dict[file_path].endswith(","):
                tmp_dict[file_path] += str(match_lines)
            else:
                tmp_dict[file_path] += "," + str(match_lines)
        details["files"] = tmp_dict
    return findings