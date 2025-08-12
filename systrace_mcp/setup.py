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

ser = "/usr/lib/systemd/system/systrac-mcpserver.service"
if os.path.isfile(ser):
    os.remove(ser)
setup(
    name="systrace_mcp",
    version="1.1.1",
    author="xu hou",
    author_email="houxu5@h-partners.com",
    description="MCP Server for SystraceFail Slow Detection for AI Model Training and Inference",
    url="https://gitee.com/openeuler/sysTrace",
    keywords=["Fail Slow Detection", "Group Compare", "AI Model", "MCP Server"],
    packages=find_packages(where=".", exclude=("tests", "tests.*")),
    data_files=[
        ('/etc/systrace/config/', glob('config/ftp_config.json')),
        ('/usr/lib/systemd/system/', glob('service/*')),
    ],
    install_requires=[
        "systrace_failslow",
        "mcp",
        "paramiko"
    ],
    entry_points={
        "console_scripts": [
            "systrace-mcpserver=systrace_mcp.mcp_server:main",
            "systrace-openapi=systrace_mcp.openapi_server:main"
        ]
    }
)