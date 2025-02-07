import os
import shutil
import json
import requests
import psutil
import frida
import sys
import time
import argparse
import ctypes
from ctypes import wintypes
import win32process
import zipfile
import winreg

# 定义Windows API的函数和数据类型
PROCESS_ALL_ACCESS = 0x1F0FFF

# ReadProcessMemory 函数原型
ReadProcessMemory = ctypes.windll.kernel32.ReadProcessMemory
ReadProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPCVOID, wintypes.LPVOID, ctypes.c_size_t,
                              ctypes.POINTER(ctypes.c_size_t)]
ReadProcessMemory.restype = wintypes.BOOL


PROCESS_NAME = "QQ.exe"
QQ_PID = None
GET_OFFSET_ADDR_URL = "https://raw.githubusercontent.com/r4inb00w/Windows_NTQQ_DB_Decrypt_Tool/refs/heads/main/QQ_Offset.json"

# 打开目标进程
def open_process(pid):
    return ctypes.windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)


# 获取模块基地址
def get_module_base_address(process_handle, module_name):
    # 获取模块句柄
    modules = win32process.EnumProcessModules(process_handle)
    for module in modules:
        module_path = win32process.GetModuleFileNameEx(process_handle, module)
        if module_name.lower() in module_path.lower():
            return module  # 返回模块基地址
    return None


# 读取内存中的值
def read_memory(process_handle, address, size):
    buffer = ctypes.create_string_buffer(size)
    bytesRead = ctypes.c_size_t(0)
    if ReadProcessMemory(process_handle, address, buffer, size, ctypes.byref(bytesRead)):
        return buffer.raw
    else:
        raise ctypes.WinError()


# 主函数
def get_online_QQID_by_pid(pid):
    module_name = "wrapper.node"  # 替换为目标模块名
    QQID_offset = json.loads(req.text)[version][1]  # 此处的offset为QQ号的相对于wrapper.node的偏移地址
    QQID_offset = int(QQID_offset, 16)
    # 获取进程句柄
    process_handle = open_process(pid)
    if not process_handle:
        print(f"无法打开PID为 {pid} 的进程")
        return

    # 获取模块基地址
    base_address = get_module_base_address(process_handle, module_name)
    if not base_address:
        print(f"模块 {module_name} 未找到")
        return


    # 读取基地址 + offset 处的值
    address_to_read = base_address + QQID_offset
    value = read_memory(process_handle, address_to_read, 10)  # 读取10个字节，
    value = bytes(value).replace(b'\x00',  b'')     #10位数以下的QQ需要去除\x00
    return str(value, encoding='utf-8')

def split_database_file(db_file_path, output_dir, file_name):
    # 确保输出目录存在
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # 读取数据库文件内容
    with open(db_file_path, 'rb') as db_file:
        content = db_file.read()
    
    # 分割文件内容
    content_header = content[:1024]
    content_body = content[1024:]
    
    # 构建输出文件路径
    header_file_path = os.path.join(output_dir, file_name + '_header.txt')
    body_file_path = os.path.join(output_dir, file_name + '_cleaned.db')
    
    # 写入头部内容
    with open(header_file_path, 'wb') as header_file:
        header_file.write(content_header)
    
    # 写入主体内容
    with open(body_file_path, 'wb') as body_file:
        body_file.write(content_body)

def clean_db_files(key, QQNum):
    output_base_directory = './cleaned'

    if not os.path.exists(args.path):
        raise FileNotFoundError(f"Tencent Files directory not found at the expected location: {args.path}")

    # 遍历所有 QQ 号目录
    for qq_number in os.listdir(args.path):
        qq_directory = os.path.join(args.path, qq_number)
        if os.path.isdir(qq_directory):
            # 构建 nt_db 目录的路径
            nt_db_directory = os.path.join(qq_directory, "nt_qq", "nt_db")
            if os.path.exists(nt_db_directory):
                for file_name in os.listdir(nt_db_directory):
                    if file_name.endswith('.db'):
                        source_path = os.path.join(nt_db_directory, file_name)
                        output_dir = os.path.join(output_base_directory, qq_number, file_name.split('.')[0])
                        split_database_file(source_path, output_dir, file_name.split('.')[0])
    print("所有.db文件已全部移除无关文件头")
    # 将密钥写入 ./cleaned 目录下的 key.txt 文件
    key_file_path = os.path.join(output_base_directory, 'key.txt')
    with open(key_file_path, 'w') as key_file:
        key_file.write(key + "  "+ QQNum)

def generate_zip_file():
    folders_to_zip = ['./cleaned']
    zip_file_name = 'QQ.zip'
    with zipfile.ZipFile(zip_file_name, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for folder in folders_to_zip:
            for root, dirs, files in os.walk(folder):
                for file in files:
                    # 创建完整的文件路径
                    file_path = os.path.join(root, file)
                    # 将文件添加到压缩包，并保存相对路径
                    zipf.write(file_path, os.path.relpath(file_path, os.path.join(folder, '..')))

# 检查并终止 QQ.exe 进程
def terminate_qq(pid=None):
    if pid is not None:
        try:
            p = psutil.Process(pid)
            try:
                print(f"Terminating QQ.exe with PID {pid}")
                p.terminate()
                p.wait()  # 等待进程终止
                print(f"QQ.exe with PID {pid} has been terminated")
            except psutil.NoSuchProcess:
                print(f"QQ.exe with PID {pid} does not exist, might have been terminated already.")
            except psutil.AccessDenied:
                print(f"Access denied when trying to terminate QQ.exe with PID {pid}.")
            except Exception as e:
                print(f"An error occurred while terminating QQ.exe with PID {pid}: {e}")
        except psutil.NoSuchProcess:
            # 忽略终止进程时的 NoSuchProcess 异常
            pass
    else:
        #若未指定pid，则终止所有QQ.exe进程
        for pid in psutil.pids():
            try:
                p = psutil.Process(pid)
                if p.name() == PROCESS_NAME:
                    try:
                        print(f"Terminating QQ.exe with PID {pid}")
                        p.terminate()
                        p.wait()  # 等待进程终止
                        print(f"QQ.exe with PID {pid} has been terminated")
                    except psutil.NoSuchProcess:
                        print(f"QQ.exe with PID {pid} does not exist, might have been terminated already.")
                    except psutil.AccessDenied:
                        print(f"Access denied when trying to terminate QQ.exe with PID {pid}.")
                    except Exception as e:
                        print(f"An error occurred while terminating QQ.exe with PID {pid}: {e}")
            except psutil.NoSuchProcess:
                # 忽略终止进程时的 NoSuchProcess 异常
                pass

def wait_for_qq():
    pids = []
    ppids = []
    for pid in psutil.pids():
        try:
            p = psutil.Process(pid)
            if p.name() == PROCESS_NAME:
                try:
                    pids.append(pid)
                    ppids.append(p.ppid())

                except psutil.NoSuchProcess:
                    print(f"QQ.exe with PID {pid} does not exist, might have been terminated already.")
                except psutil.AccessDenied:
                    print(f"Access denied when trying to terminate QQ.exe with PID {pid}.")
                except Exception as e:
                    print(f"An error occurred while terminating QQ.exe with PID {pid}: {e}")
        except psutil.NoSuchProcess:
            pass
    QQ_PIDs = set(pids) & set(ppids)  # 获取NTQQ主进程
    for pid in QQ_PIDs:
        if pid in result_list.keys():
            print("QQ.exe not found. Waiting for it to start...")
            time.sleep(3)  # 等待 5 秒后重新检查
            return None
        else:
            return pid

# 等待 QQ.exe 进程启动
def wait_for_qq_by_flag(flag=False):
    global QQ_PID
    QQ_PID = None
    if flag:    #flag为True则代表根据等待另一个登录的QQ账号
        QQ_PID = wait_for_qq()
        while QQ_PID is None:
            QQ_PID = wait_for_qq()
    else:
        while QQ_PID is None:
            QQ_PID = wait_for_qq()

def on_message(message, data):
    if message['type'] == 'send':
        if 'key' in message['payload']:
            key = message['payload']['key']
            print(f"key: {key}")
            get_db_file(key)

            os._exit(0)  # 使用 os._exit(0) 结束 Python 脚本
        else:
            print("[*] {0}".format(message['payload']))
    elif message['type'] == 'error':
        print("[!] {0}".format(message['stack']))
        session.detach()  # Detach the session if there is an error
        wait_for_qq_by_flag()  # 重新等待 QQ.exe 启动
        attach_to_qq()  # 再次附加到 QQ.exe

def get_db_file(key):
    clean_db_files(key, get_online_QQID_by_pid(QQ_PID))
    # decrypt_db_files(key, get_online_QQID_by_pid(QQ_PID))
    generate_zip_file()
    try:
        shutil.rmtree('./cleaned')
    except Exception as e:
        pass

def get_qq_version():
    try:
        # 打开注册表键
        registry_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Tencent\QQNT", 0, winreg.KEY_READ)
        # 读取指定值
        value, reg_type = winreg.QueryValueEx(registry_key, "version")
        winreg.CloseKey(registry_key)
        return value
    except FileNotFoundError:
        return None

# 附加到 QQ.exe 进程并加载脚本
def attach_to_qq():
    global session
    try:
        session = frida.attach(QQ_PID)
        # 创建并加载脚本
        script = session.create_script(script_content)
        script.on('message', on_message)
        script.load()

        print(f"Script loaded and attached to QQ.exe with PID {QQ_PID}.")
        sys.stdin.read()

    except frida.ProcessNotRespondingError as e:
        print(f"Frida ProcessNotRespondingError: {e}")
        wait_for_qq_by_flag()  # 重新等待 QQ.exe 启动
        attach_to_qq()  # 再次附加到 QQ.exe
    except frida.ProcessNotFoundError:
        print(f"Process 'QQ.exe' not found.")
        wait_for_qq_by_flag()  # 重新等待 QQ.exe 启动
        attach_to_qq()  # 再次附加到 QQ.exe
    except Exception as e:
        print(f"An error occurred: {e}")
        wait_for_qq_by_flag()  # 重新等待 QQ.exe 启动
        attach_to_qq()  # 再次附加到 QQ.exe

def get_QQ_list():
    pids = []
    ppids = []
    for pid in psutil.pids():
        try:
            p = psutil.Process(pid)
            if p.name() == PROCESS_NAME:
                try:
                    pids.append(pid)
                    ppids.append(p.ppid())

                except psutil.NoSuchProcess:
                    print(f"QQ.exe with PID {pid} does not exist, might have been terminated already.")
                except psutil.AccessDenied:
                    print(f"Access denied when trying to terminate QQ.exe with PID {pid}.")
                except Exception as e:
                    print(f"An error occurred while terminating QQ.exe with PID {pid}: {e}")
        except psutil.NoSuchProcess:
            pass
    QQ_PIDs = set(pids) & set(ppids)    #获取NTQQ主进程
    result = {}
    for pid in QQ_PIDs:
        result[pid] = get_online_QQID_by_pid(pid)
    return result

def get_key_by_pid(pid):
    # 终止指定pid对应的QQ.exe进程
    terminate_qq(pid)
    result_list.pop(pid)
    # 等待用户重新登录 QQ
    print("Waiting for QQ to restart...")
    wait_for_qq_by_flag(True)
    print("Selected QQ pid is:", QQ_PID)
    # 等待 QQ.exe 启动并附加
    attach_to_qq()

if __name__ == "__main__":
    #获取QQ版本号
    req = requests.get(GET_OFFSET_ADDR_URL)
    try:
        version = get_qq_version()
    except Exception as e:
        version = list(dict(json.loads(req.text)).keys())[-1]  # 若注册表获取版本号失败，将version设置为QQ最新版本号
    # 获取当前用户的 USERPROFILE 环境变量
    user_profile = os.environ.get("USERPROFILE")
    if not user_profile:
        raise EnvironmentError("USERPROFILE environment variable not found.")

    # 构建 Tencent Files 目录路径
    tencent_files_directory = os.path.join(user_profile, "Documents", "Tencent Files")
    parser = argparse.ArgumentParser()
    parser.add_argument('--path', type=str, default=tencent_files_directory, help=r'指定Tencent Files 目录路径，Defalut: C:\Users\{username}\Documents\Tencent Files')
    parser.add_argument('--qqVersion', action='store_true', help='获取当前计算机的QQ版本号')
    parser.add_argument('--list', action='store_true', help='列出QQ进程对应的PID以及此PID对应的QQ账号')
    parser.add_argument('--pid', type=int, default=None, help='获取该进程对应的QQ账号解密后的聊天数据库 (NTQQ启动后会有多个进程，请注意区分是main process还是renderer process)')
    parser.add_argument('--qq', type=str, default=None, help='获取该QQ账号解密后的聊天数据库')
    # 解析命令行参数
    args = parser.parse_args()
    if args.list:
        result_list = get_QQ_list()
        print("PID" + " " * 15 + "QQ ID")
        for key, value in result_list.items():
            print(str(key) + " " * (15 - (len(str(key)) - 3)) + value)
        os._exit(0)
    if args.qqVersion:
        current_qqVersion = get_qq_version()
        sys.stdout.write("QQ版本号为：" + current_qqVersion)
        valid_qqVersion = list(dict(json.loads(req.text)).keys())
        print("目前支持的版本号：", valid_qqVersion)
        if current_qqVersion not in valid_qqVersion:
            print("需要自行分析偏移地址，并添加至{}".format(GET_OFFSET_ADDR_URL) + "中，格式为:{版本号: [nt_sqlite3_key_v2 Offset, QQNumber Offset]}")
        os._exit(0)
    result_list = get_QQ_list()
    # 根据版本调整函数offset
    key_offset = json.loads(req.text)[version][0]
    print(key_offset)
    script_content = """(function () {
    var outputCount = 0;
    function read_string_at_offset(addr, offset, length) {
        var targetAddr = addr.add(offset);
        return Memory.readUtf8String(targetAddr, length);
    }

    function hook_native_addr(funcPtr, paramsNum) {
        console.log(funcPtr);
        var module = Process.findModuleByAddress(funcPtr);
        try {
            Interceptor.attach(funcPtr, {
                onEnter: function (args) {
                    outputCount++;
                    if (outputCount >= 5) {
                        this.logs = "";
                        var targetOffset = 0;
                        var targetLength = 16;
                        var key = read_string_at_offset(args[2], targetOffset, targetLength);
                        send({ key: key });
    
                        Interceptor.detachAll();
                    }
                }
            });
        } catch (e) {
            console.log(e);
        }
    }

    hook_native_addr(Module.findBaseAddress("wrapper.node").add(""" + key_offset +"""), 0x4);
})();
"""
    if args.pid or args.qq:
        if args.pid:
            valid_pid = result_list.keys()
            if args.pid not in valid_pid:
                print("The PID is not valid.")
            else:
                get_key_by_pid(args.pid)
        else:
            valid_qq = result_list.values()
            if args.qq not in valid_qq:
                print("The QQ is not valid.")
            else:
                for key,value in result_list.items():
                    if value == args.qq:
                        get_key_by_pid(key)
    else:
        # 检查并终止现有的 QQ.exe 进程
        terminate_qq()
        # 等待用户重新登录 QQ
        print("Waiting for QQ to restart...")
        wait_for_qq_by_flag()
        print("Selected QQ pid is:", QQ_PID)

        # 等待 QQ.exe 启动并附加
        attach_to_qq()
