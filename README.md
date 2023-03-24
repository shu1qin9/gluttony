# shui'scan漏扫框架

该工具主要用于日常渗透测试，为了方便将繁琐冗余的操作自动化

系统采用主要的技术栈：RichConsole(控制台)、concurrent.futures(多线程)、loguru(log记录)

目前工具仅有俩个模块：scan、mobile

## scan

该模块用于常规漏洞扫描，漏扫核心是读取对应文件下的py文件，并依据用户需求来做 _verify(poc验证)、_attack(攻击)操作

py漏洞payload的编写可以完全依据模板文件：**lib/core/base/exploits.py** 填充即可

### exploits.py 文件说明

用户自行编写payload时，创建class继承`Exploits`类

而后重写`__init__`方法，并super继承，其中`self.vulnerability`均有注释说明，依据自己情况填写即可

其中需要注意的是，如果漏洞存在exp模式，则将`attack`参数置于true，而后重写`_attack`方法

_verify 方法的运行结束后，如果存在漏洞，需要将`self.vulnerability["vulnerable"]`值置为`True`，并且结果保存在 `self.vulnerability["result"]`

_attack 方法在漏洞利用阶段，可以使用`console.input`来接收用户参数

## mobile

该模块用于移动端漏洞扫描，此模块目前还在开发中，lib的公用部分没有开发完成

# 版本更新

## v1.0

该版本完成了漏扫的整体框架搭建，以及常规漏扫的植入验证