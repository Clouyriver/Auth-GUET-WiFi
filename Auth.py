import re
import subprocess
import socket
from typing import Dict, List, Optional
from collections import defaultdict
import base64
import requests
import platform
from pathlib import Path

InterfaceInfo = Dict[str, Dict[str, List[str] | Optional[str]]]


def get_network_info():
    """获取网络接口的IP和MAC地址信息(支持Windows和Linux)"""
    system = platform.system().lower()
    interfaces: InterfaceInfo = defaultdict(lambda: {"ipv4": [], "ipv6": [], "mac": None})
    if system == "windows":
        # Windows系统
        try:
            # 获取网络接口信息
            output = subprocess.check_output(
                ["ipconfig", "/all"],
                encoding="oem"  # 使用系统编码
            ).lower()
        except subprocess.CalledProcessError:
            return interfaces

        # 解析输出
        current_adapter = None
        for line in output.split("\n"):
            # 检测适配器名称
            adapter_match = re.search(r"wlan (\d+):$", line)
            if adapter_match:
                # 获取当前适配器名称
                current_adapter = adapter_match.group().strip()
                continue

            if current_adapter:
                # 提取MAC地址
                mac_match = re.search(r"物理地址[. ]+: ([0-9a-f-]+)", line)
                if mac_match:
                    mac = mac_match.group(1).replace("-", ":")
                    interfaces[current_adapter]["mac"] = mac

                # 提取IPv4地址
                ipv4_match = re.search(r"ipv4 地址[. ]+: ([0-9.]+)", line)
                if ipv4_match:
                    ipv4_addr = ipv4_match.group(1)
                    # 过滤掉链路本地地址
                    if not ipv4_addr.startswith("127") and not ipv4_addr.startswith("192"):
                        interfaces[current_adapter]['ipv4'].append(ipv4_addr)

                # 提取IPv6地址
                ipv6_match = re.search(r"ipv6 地址[. ]+: ([0-9a-f:%]+)", line)
                if ipv6_match:
                    ipv6_addr = ipv6_match.group(1)
                    # 过滤掉链路本地地址
                    if not ipv6_addr.startswith('fe80') and not ipv6_addr.startswith("::1"):
                        interfaces[current_adapter]['ipv6'].append(ipv6_addr)


    elif system == "linux":
        # Linux系统
        try:
            # 检测适配器名称
            output = subprocess.check_output(
                ["ifconfig"],
                encoding="utf-8"
            )
        except (subprocess.CalledProcessError, FileNotFoundError):
            return interfaces

        # 解析输出
        current_adapter = None
        for line in output.split('\n'):
            # 检测适配器名称
            adapter_match = re.search(r'^([a-zA-Z]+(\d+)):', line)
            if adapter_match:
                # 提取当期适配器名称
                current_adapter = adapter_match.group().strip()
                continue

            if current_adapter:
                # 提取MAC地址
                mac_match = re.search(r'ether ([0-9a-f:]+)', line)
                if mac_match:
                    mac = mac_match.group().replace("ether ", "")
                    interfaces[current_adapter]['mac'] = mac

                # 提取IPv4地址
                ipv4_match = re.search(r'inet ([0-9.]+)', line)
                if ipv4_match:
                    interfaces[current_adapter]['ipv4'].append(ipv4_match.group(1))

                # 提取IPv6地址
                ipv6_match = re.search(r'inet6 ([0-9a-f:%]+)', line)
                if ipv6_match:
                    ipv6_addr = ipv6_match.group(1)
                    # 过滤掉链路本地地址
                    if not ipv6_addr.startswith('fe80') and not ipv6_addr.startswith("::1"):
                        interfaces[current_adapter]['ipv6'].append(ipv6_addr)

    # 添加主机名
    hostname = socket.gethostname()
    interfaces["hostname"] = {
        "name": hostname,
        "ipv4": socket.gethostbyname_ex(hostname)[2]
    }

    return interfaces


headers = {
    "Accept": "*/*",
    "Accept-Encoding": "gzip, deflate",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,ko;q=0.7",
    "Connection": "keep-alive",
    "Host": "10.0.1.5",
    "Referer": "http://10.0.1.5/",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36"
}


def get_config_path():
    """根据操作系统获取配置文件路径"""
    system = platform.system()

    if system == "Windows":
        # Windows系统保存在用户目录下
        config_path = Path.home() / "GUET-WiFi-Config.txt"
    elif system == "Linux":
        # Linux下隐藏文件
        config_path = Path.home() / ".guet_wifi_config"
    else:
        # 其他系统默认保存在当前目录
        config_path = Path("GUET-WiFi-Config.txt")

    return config_path


def get_user_input():
    """获取用户输入的信息"""
    # 获取用户名和密码和认证方式
    global auth_info
    account = str(input('请输入账号:'))
    # 密码
    password = str(input('请输入密码:'))
    # 认证方式
    while True:
        auth_way = str(input("请输入认证方式 (0.校园网 1.移动 2.联通 3.电信): "))
        if auth_way == "0":
            auth_info = ""
            break
        elif auth_way == "1":
            auth_info = "cmcc"
            break
        elif auth_way == "2":
            auth_info = "unicom"
            break
        elif auth_way == "3":
            auth_info = "telecom"
            break
        else:
            print("请输入正确的认证方式 (0/1/2/3)")
            continue

    return account, password, auth_way, auth_info


def load_config():
    """从配置文件加载信息"""
    # 获取配置文件路径
    config_file_path = get_config_path()

    try:
        with open(config_file_path, "r") as f:
            lines = f.readlines()
            if len(lines) >= 3:
                account = lines[0].strip()
                password = lines[1].strip()
                auth_way = lines[2].strip()

                # 根据认证方式设置auth_info
                auth_info = ""
                if auth_way == "1":
                    auth_info = "cmcc"
                elif auth_way == "2":
                    auth_info = "unicom"
                elif auth_way == "3":
                    auth_info = "telecom"

                return account, password, auth_way, auth_info
            else:
                return None
    except FileNotFoundError:
        return None


def save_config(account, password, auth_way):
    """保存配置到文件"""
    # 获取配置文件路径
    config_file_path = get_config_path()

    with open(config_file_path, "w") as f:
        f.write(account + "\n" + password + "\n" + auth_way)

    print(f"配置已保存到: {config_file_path}")


def sign_in():
    # 获取网络信息
    info = get_network_info()

    # 账户和密码和认证方式
    account_info = ""
    password_info = ""
    auth_way = ""
    auth_info = ""
    account = ""
    password = ""
    isConfig = False

    # 尝试从配置文件加载信息
    config_data = load_config()
    if config_data:
        account, password, auth_way, auth_info = config_data
        isConfig = True
        print(f'已从{get_config_path()}加载用户信息')
    else:
        # 如果没有配置文件，则获取用户输入
        account, password, auth_way, auth_info = get_user_input()
        # 保存配置
        save_config(account, password, auth_way)

    # 处理账号,密码和认证方式
    if auth_way != "0":
        account_info = f"%2C0%2{account}%40{auth_info}"
    else:
        account_info = f"%2C0%2{account}"

    # 密码进行base64加密
    password_info = base64.b64encode(password.encode("ascii")).decode("ascii")

    # 从返回的数据结构中获取IP和MAC地址
    ip = ""
    mac = ""

    # 遍历所有适配器找到以10.33开头的IP地址
    for adapter, data in info.items():
        if data["ipv4"] and data["mac"]:
            ips = data["ipv4"]
            for ip_need_config in ips:
                if ip_need_config.startswith("10.33."):
                    ip = ip_need_config
                    mac = data["mac"]
                    break
        # 如果找到了符合条件的IP,跳出外层循环
        if ip.startswith("10.33"):
            break

    # 如果没找到,使用默认值
    if not ip.startswith("10.33"):
        raise ValueError("IP必须是10.33开头")
    if not mac:
        mac = "00:00:00:00:00:00"

    print("Account:", account)
    print("IP:", ip)
    print("MAC:", mac)
    mac = mac.replace(":", "")

    # 随机4位数
    v = str(int(1000 * (1 + 9 * (1 - 0.5))))

    # 构建请求参数
    sign_parameter = ("http://10.0.1.5:801/eportal/portal/login?" +
                      "callback=dr1003&" +
                      "login_method=1&" +
                      "user_account=" + account_info + "&" +
                      "user_password=" + password_info + "&" +
                      "wlan_user_ip=" + ip + "&" +
                      "wlan_user_ipv6=&" +
                      "wlan_user_mac=" + mac + "&" +
                      "wlan_ac_ip=10.32.255.10&" +
                      "wlan_ac_name=HJ-BRAS-ME60-01&jsVersion=4.2&" +
                      "terminal_type=1&" +
                      "lang=zh-cn&" +
                      "v=" + v + "&" +
                      "lang=zh")
    print(sign_parameter)

    # 如果需要发送请求
    response = requests.get(sign_parameter, headers=headers)
    print(response.text)

    if response.status_code == 200 and isConfig != True:
        # 保存配置
        save_config(account, password, auth_way)

    # 暂停
    input("按任意键退出...")


if __name__ == "__main__":
    sign_in()
