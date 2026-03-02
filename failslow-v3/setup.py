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
import os

from setuptools import setup, find_packages

# 清理旧版本配置文件
cfg_path = "/etc/systrace"
if os.path.exists(cfg_path):
    for root, dirs, files in os.walk(cfg_path):
        for file in files:
            file_path = os.path.join(root, file)
            if os.path.isfile(file_path):
                os.remove(file_path)

# 清理旧版本 systemd service
for ser in (
    "/usr/lib/systemd/system/systrace-failslow.service",
):
    if os.path.isfile(ser):
        os.remove(ser)

setup(
    name="systrace_failslow",
    version="1.3.0",
    author="bin huang",
    author_email="huangbin58@huawei.com",
    description="Fail Slow Detection for AI Model Training and Inference",
    url="https://gitcode.com/openeuler/sysTrace",
    keywords=["Fail Slow Detection", "Group Compare", "AI Model"],
    packages=find_packages(exclude=["test*"]),
    data_files=[
        ("/etc/systrace/config/", glob("config/*.json")),
        ("/usr/lib/systemd/system/", glob("service/*.service")),
    ],
    install_requires=[
        "numpy>=1.19.0,<2.0.0",
        "pandas>=1.2.0",
        "pydantic>=1.10.0",
        "scipy>=1.6.0",
        "scikit-learn>=0.24.0",
        "matplotlib>=3.3.0",
    ],
    entry_points={
        "console_scripts": [
            "systrace-failslow=failslow.entrypoints.main:main",
            "systrace-failslow-server=failslow.entrypoints.multi_node_server:main",
            "systrace-failslow-agent=failslow.entrypoints.multi_node_agent:main",
        ]
    },
)
