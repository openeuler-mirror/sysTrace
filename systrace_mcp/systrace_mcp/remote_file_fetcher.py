import shutil

import paramiko
from datetime import datetime
import json
import os
from stat import S_ISDIR
import sys
from failslow.util.constant import  MODEL_CONFIG_PATH
import logging
import sys
# 配置日志系统
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("systrace_mcpserver")
FTP_CONFIG_PATH = "/etc/systrace/config/ftp_config.json"

class UnsupportedSyncTypeError(Exception):
    """自定义异常类，用于处理不支持的同步类型"""

    def __init__(self, sync_type):
        self.sync_type = sync_type
        super().__init__(f"不支持的同步类型: {sync_type}，仅支持 'perception' 和 'detection'")


def load_config(config_file):
    """加载并解析多服务器JSON配置文件"""
    try:
        # 解析配置文件的绝对路径
        abs_config_path = os.path.abspath(config_file)
        if not os.path.exists(abs_config_path):
            print(f"错误: 配置文件 {abs_config_path} 不存在")
            return None

        with open(abs_config_path, 'r') as f:
            config = json.load(f)

        # 验证配置结构
        if "servers" not in config or not isinstance(config["servers"], list):
            logger.info("错误: 配置文件格式不正确，缺少servers数组")
            return None

        # 验证每个服务器配置的必要项
        required_keys = [
            "ip", "port", "user", "password",
            "perception_remote_dir", "detection_remote_dir"
        ]

        for idx, server in enumerate(config["servers"]):
            for key in required_keys:
                if key not in server:
                    logger.info(f"错误: 服务器配置 #{idx + 1} 缺少必要项 {key}")
                    return None

            # 标准化远程目录路径
            server["perception_remote_dir"] = server["perception_remote_dir"].replace("\\", "/")
            if not server["perception_remote_dir"].endswith("/"):
                server["perception_remote_dir"] += "/"

            server["detection_remote_dir"] = server["detection_remote_dir"].replace("\\", "/")
            if not server["detection_remote_dir"].endswith("/"):
                server["detection_remote_dir"] += "/"

        return config["servers"]

    except json.JSONDecodeError:
        logger.info(f"错误: 配置文件 {config_file} 格式不正确")
        return None
    except Exception as e:
        logger.info(f"加载配置文件时发生错误: {str(e)}")
        return None


def get_server_config(servers, target_ip):
    """根据IP查找对应的服务器配置"""
    for server in servers:
        if server["ip"] == target_ip:
            return server
    logger.info(f"错误: 未找到IP为 {target_ip} 的服务器配置")
    return None


def resolve_local_dir(local_dir):
    """
    解析本地目录路径，将相对路径转换为绝对路径
    相对路径是相对于当前脚本的执行目录，而不是配置文件的位置
    """
    # 如果是绝对路径，直接返回
    if os.path.isabs(local_dir):
        return local_dir

    # 如果是相对路径，基于当前工作目录解析
    return os.path.abspath(os.path.join(os.getcwd(), local_dir))


def init_local_dir(local_dir):
    """初始化本地目录，确保目录存在且为空"""
    # 解析路径（处理相对路径）
    resolved_dir = resolve_local_dir(local_dir)  # 假设resolve_local_dir已实现路径解析功能
    normalized_dir = os.path.normpath(resolved_dir)

    # 如果目录存在
    if os.path.exists(normalized_dir):
        # 检查目录是否为空
        if os.listdir(normalized_dir):
            # 遍历目录内容并删除
            for item in os.listdir(normalized_dir):
                item_path = os.path.join(normalized_dir, item)
                try:
                    if os.path.isfile(item_path) or os.path.islink(item_path):
                        os.unlink(item_path)  # 删除文件或软链接
                        logger.info(f"删除文件: {item_path}")
                    elif os.path.isdir(item_path):
                        shutil.rmtree(item_path)  # 删除子目录及其内容
                        logger.info(f"删除目录: {item_path}")
                except Exception as e:
                    logger.info(f"删除 {item_path} 失败: {e}")
            logger.info(f"已清空目录: {normalized_dir}")
        else:
            logger.info(f"目录已存在且为空: {normalized_dir}")
    else:
        # 创建目录（包括必要的父目录）
        os.makedirs(normalized_dir, exist_ok=True)
        logger.info(f"创建本地根目录: {normalized_dir}")

    return normalized_dir


def get_remote_files_recursive(sftp, remote_base_dir, current_dir):
    """递归获取远程目录所有文件"""
    all_files = []

    try:
        current_dir = current_dir.replace("\\", "/")
        if not current_dir.endswith("/"):
            current_dir += "/"

        for entry in sftp.listdir_attr(current_dir):
            entry_remote_path = f"{current_dir}{entry.filename}"

            if entry.filename.startswith('.'):
                continue

            if S_ISDIR(entry.st_mode):
                subdir_files = get_remote_files_recursive(sftp, remote_base_dir, entry_remote_path)
                all_files.extend(subdir_files)
            else:
                relative_path = entry_remote_path[len(remote_base_dir):]
                all_files.append({
                    "name": entry.filename,
                    "remote_path": entry_remote_path,
                    "relative_path": relative_path,
                    "mtime": datetime.fromtimestamp(entry.st_mtime)
                })

        return all_files

    except Exception as e:
        logger.info(f"获取远程文件列表失败 (目录: {current_dir}): {e}")
        return []


def download_new_files(sftp, remote_files, local_root):
    """下载新增或更新的文件，保持目录结构"""
    # 确保本地根目录已正确解析
    resolved_local_root = resolve_local_dir(local_root)

    for file in remote_files:
        local_relative_path = file["relative_path"].replace("/", os.sep)
        # 构建完整本地路径
        local_file_path = os.path.normpath(os.path.join(resolved_local_root, local_relative_path))
        local_file_dir = os.path.dirname(local_file_path)

        # 确保本地目录存在
        if not os.path.exists(local_file_dir):
            os.makedirs(local_file_dir, exist_ok=True)
            logger.info(f"创建本地子目录: {local_file_dir}")

        # 检查文件是否需要下载或更新
        if not os.path.exists(local_file_path):
            logger.info(f"下载新文件: {file['remote_path']} -> {local_file_path}")
            sftp.get(file["remote_path"], local_file_path)
        else:
            local_mtime = datetime.fromtimestamp(os.path.getmtime(local_file_path))
            if file["mtime"] > local_mtime:
                logger.info(f"更新文件: {file['remote_path']} -> {local_file_path}")
                sftp.get(file["remote_path"], local_file_path)


def getServer_config(target_ip):
    # 加载配置
    servers = load_config(FTP_CONFIG_PATH)
    if not servers:
        return False

    # 获取目标服务器配置
    server_config = get_server_config(servers, target_ip)
    if not server_config:
        return False
    return server_config


def getEnable_config():
    # 加载配置
    """加载并解析多服务器JSON配置文件"""
    try:
        # 解析配置文件的绝对路径
        abs_config_path = os.path.abspath(FTP_CONFIG_PATH)
        if not os.path.exists(abs_config_path):
            logger.info(f"错误: 配置文件 {abs_config_path} 不存在")
            return None

        with open(abs_config_path, 'r') as f:
            config = json.load(f)
            return config["enable"]

    except json.JSONDecodeError:
        logger.info(f"错误: 配置文件 {FTP_CONFIG_PATH} 格式不正确")
        return None
    except Exception as e:
        logger.info(f"加载配置文件时发生错误: {str(e)}")
        return None


def sync_server_by_ip_and_type(target_ip, sync_type)->bool:
    """根据IP和同步类型同步指定服务器的文件"""
    # 判断一下同步功能是否开启
    if getEnable_config() == 'False':
        return True
    logger.info(f"{datetime.now()} - 开始同步服务器 {target_ip} 的 {sync_type} 类型文件...")

    # 验证同步类型
    if sync_type not in ["perception", "detection"]:
        try:
            raise UnsupportedSyncTypeError(sync_type)
        except UnsupportedSyncTypeError as e:
            raise ValueError(f"同步数据类型异常")
    server_config = getServer_config(target_ip)
    with open(MODEL_CONFIG_PATH, 'r', encoding='utf-8') as reader:
        model_args = json.load(reader)
    try:
        # 根据同步类型选择对应的目录
        if sync_type == "perception":
            remote_dir = server_config["perception_remote_dir"]
            local_dir =  os.path.dirname(model_args["training_log"])
        else:  # detection
            remote_dir = server_config["detection_remote_dir"]
            local_dir = model_args["root_path"]

        # 解析并初始化本地目录
        resolved_local_dir = resolve_local_dir(local_dir)
        logger.info(f"使用本地目录: {resolved_local_dir}")
        local_root = init_local_dir(resolved_local_dir)

        # 建立SSH连接
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(
            server_config["ip"],
            server_config["port"],
            server_config["user"],
            server_config["password"]
        )

        # 创建SFTP客户端
        sftp = ssh.open_sftp()

        # 递归获取所有远程文件
        remote_files = get_remote_files_recursive(
            sftp,
            remote_dir,  # 远程根目录
            remote_dir  # 初始当前目录
        )

        if remote_files:
            logger.info(f"发现 {len(remote_files)} 个远程文件（包括所有子目录），开始同步...")
            download_new_files(sftp, remote_files, local_root)
        else:
            raise ValueError(f"未发现 {sync_type} 类型的远程文件")

        # 关闭连接
        sftp.close()
        ssh.close()
        logger.info(f"{datetime.now()} - 服务器 {target_ip} 的 {sync_type} 类型文件同步完成")
        return True

    except Exception as e:
        raise ValueError(f"获取远程服务器systrace采集数据异常: {e}")


# 使用示例
if __name__ == "__main__":
    # 同步detection类型，会使用配置中的"detection_local_dir"
    sync_server_by_ip_and_type("9.13.100.7", "perception")

    # 同步perception类型
    # sync_server_by_ip_and_type("76.53.17.51", "perception")
