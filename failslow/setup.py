#!/usr/bin/python3
# ******************************************************************************
# Copyright (c) 2022 Huawei Technologies Co., Ltd.
# gala-anteater is licensed under Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#          http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.
# ******************************************************************************/

from glob import glob

from setuptools import setup, find_packages
import os 

# 安装前清理旧版本配置文件
cfg_path = "/etc/systrace"
for root, dirs, files in os.walk(cfg_path):
    for file in files:
        os.remove(os.path.join(root, file))

ser = "/usr/lib/systemd/system/systrac-failslow.service"
if os.path.isfile(ser):
    os.remove(ser)

setup(
    name="systrace_failslow",
    version="1.0.0",
    author="bin huang",
    author_email="huangbin58@huawei.com",
    description="Fail Slow Detection for AI Model Training and Inference",
    url="https://gitee.com/openeuler/sysTrace",
    keywords=["Fail Slow Detection", "Group Compare", "AI Model"],
    packages=find_packages(where=".", exclude=("tests", "tests.*")),
    data_files=[
        ('/etc/systrace/config/', glob('config/metric_config.json')),
        ('/etc/systrace/config/', glob('config/model_config.json')),
        ('/usr/lib/systemd/system/', glob('service/*')),
    ],
    install_requires=[
        "numpy",
        "pandas",
        "matplotlib",
        "joblib",
        "scikit_learn",
    ],
    entry_points={
        "console_scripts": [
            "systrace-failslow=failslow.main:main",
        ]
    }
)
