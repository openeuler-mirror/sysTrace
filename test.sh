#!/bin/bash
# 颜色定义
COLOR_INFO='\033[34m'    # 蓝色信息
COLOR_SUCCESS='\033[32m' # 绿色成功
COLOR_ERROR='\033[31m'   # 红色错误
COLOR_WARNING='\033[33m' # 黄色警告
COLOR_RESET='\033[0m'    # 重置颜色


#管理员权限启动
if [[ $(id -u) -ne 0 ]]; then
  echo -e "${COLOR_ERROR}[Error] 请以root权限运行该脚本！${COLOR_RESET}"
  return 1
fi
#添加代理
export http_proxy=http://peulerosci:EulerOS_123@proxy.huawei.com:8080
export https_proxy=http://peulerosci:EulerOS_123@proxy.huawei.com:8080
export no_proxy=127.0.0.1

#换源
echo "更新yum源"
echo "[SHELL]
name=SHELL
baseurl=https://eulermaker.compass-ci.openeuler.openatom.cn/api/ems1/repositories/framework-agent/openEuler%3A24.03-LTS-SP2/x86_64/
enabled=1
gpgcheck=0
sslverify=0
gpgkey=http://repo.openeuler.org/openEuler-24.03-LTS-SP2/OS//RPM-GPG-KEY-openEuler">>/etc/yum.repos.d/shell.repo

yum clean all
yum makecache

#启动perf
git config --global http.sslVerify false
cd /home
git clone https://gitee.com/zxstty/perf_mcp
dnf install -y python3-devel python3-pip perf
pip install pyyaml psutil mcp==1.6.0 -i https://pypi.tuna.tsinghua.edu.cn/simple --trusted-host pypi.tuna.tsinghua.edu.cn
cd perf_mcp
firewall-cmd --permanent --add-port=12141/tcp
firewall-cmd --reload
nohup python3 src/server.py >perf_mcp.log 2>&1 &

#安装rpm
dnf install -y openeuler-intelligence-cli openeuler-intelligence-installer

#修改配置文件
cd /usr/lib/openeuler-intelligence/scripts/5-resource
sed -i.bak \
    -e '/^\[llm\]$/,/^\[.*\]$/ s|^endpoint = .*|endpoint = "https://api.deepseek.com"|' \
    -e '/^\[llm\]$/,/^\[.*\]$/ s|^key = .*|key = "sk-440510c3614a488283f389834085e173"|' \
    -e '/^\[llm\]$/,/^\[.*\]$/ s|^model = .*|model = "deepseek-chat"|' \
    -e '/^\[function_call\]$/,/^\[.*\]$/ s|^backend = .*|backend = "openai"|' \
    -e '/^\[function_call\]$/,/^\[.*\]$/ s|^endpoint = .*|endpoint = "https://api.deepseek.com"|' \
    -e '/^\[function_call\]$/,/^\[.*\]$/ s|^model = .*|model = "deepseek-chat"|' \
    -e '/^\[function_call\]$/,/^\[.*\]$/ s|^api_key = .*|api_key = "sk-440510c3614a488283f389834085e173"|' \
    config.toml

FRAMEWORK_FILE="framework.service"

if [ ! -f "$FRAMEWORK_FILE" ]; then
    echo "错误：文件 $FRAMEWORK_FILE 不存在！"
    exit 1
fi
echo '[Unit]
After=network.target nss-lookup.target
[Service]
User=root
WorkingDirectory=/usr/lib/euler-copilot-framework
Environment="PYTHONPATH=/usr/lib/euler-copilot-framework"
Environment="CONFIG=/etc/euler-copilot-framework/config.toml"
Environment="http_proxy=http://peulerosci:EulerOS_123@proxy.huawei.com:8080"
Environment="https_proxy=http://peulerosci:EulerOS_123@proxy.huawei.com:8080"
Environment="no_proxy=127.0.0.1"
ExecStart=/usr/bin/python3 apps/main.py
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=10
LimitNOFILE=infinity
[Install]
WantedBy=multi-user.target' > "$FRAMEWORK_FILE"

CLIENT_FILE="/usr/lib/python3.11/site-packages/openai/_base_client.py"

if [ ! -f "$CLIENT_FILE" ]; then
    echo "openai未安装 安装中"
    dnf install -y python3-openai
fi
sed -i.bak -E '/(Sync|Async)HttpxClientWrapper\($/,/timeout=cast\(Timeout, timeout\),/ {
    /timeout=cast\(Timeout, timeout\),/ a\            verify=False
}' "$CLIENT_FILE"

#启动
openeuler-intelligence-installer
echo "开始初始化智能助手"
sleep 5
JSON_FILE="/usr/lib/openeuler-intelligence/scripts/5-resource/mcp_config/perf_mcp/config.json"

if [ ! -f "$JSON_FILE" ]; then
    echo "错误：文件 $JSON_FILE 不存在！"
    exit 1
fi

sed -i.bak 's/"perf 分析工具"/"OS智能助手"/g' "$JSON_FILE"

openeuler-intelligence-installer --a init /usr/lib/openeuler-intelligence/scripts/5-resource/mcp_config/perf_mcp/config.json
openeuler-intelligence-installer --a create /usr/lib/openeuler-intelligence/scripts/5-resource/mcp_config/perf_mcp/config.json

echo "请在命令行输入 oi 进入 shell端使用界面 "