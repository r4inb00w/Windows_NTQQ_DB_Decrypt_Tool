import os
from pysqlcipher3 import dbapi2 as sqlite
import QQ_Message_pb2
import emoji
import argparse
import time

def decrypt_db_files(cleaned_db_path):
    output_base_directory = './decrypted'

    key_path = os.path.join(cleaned_db_path, "key.txt")
    decrypt_key = {}
    with open(key_path, 'r') as f:
        content = f.readline()
        decrypt_key[content.split()[1]] = content.split()[0]

    for qq_number in os.listdir(cleaned_db_path):
        if qq_number in decrypt_key.keys():
            qq_directory = os.path.join(cleaned_db_path, qq_number)
            if os.path.isdir(qq_directory):
                # 遍历 QQ 号目录下的所有 .db 文件
                for file_dir in os.listdir(qq_directory):
                    data_directory = os.path.join(qq_directory, file_dir)
                    for file_name in os.listdir(data_directory):
                        if file_name.endswith('.db'):
                            cleaned_db_file_path = os.path.join(data_directory, file_name)
                            output_dir = os.path.join(output_base_directory, qq_number, file_dir)
                            os.makedirs(output_dir, exist_ok=True)
                            decrypted_db_file_path = os.path.join(output_dir, file_dir + '_decrypted.db')
                            conn = None
                            try:
                                conn = sqlite.connect(cleaned_db_file_path)
                                cursor = conn.cursor()
                                cursor.execute(f"PRAGMA key = '{decrypt_key[qq_number]}';")
                                cursor.execute("PRAGMA cipher_page_size = 4096;")
                                cursor.execute("PRAGMA kdf_iter = 4000;")
                                cursor.execute("PRAGMA cipher_hmac_algorithm = HMAC_SHA1;")
                                cursor.execute("PRAGMA cipher_default_kdf_algorithm = PBKDF2_HMAC_SHA512;")
                                cursor.execute("PRAGMA cipher = 'aes-256-cbc';")
                                cursor.execute("BEGIN;")
                                cursor.execute(f"ATTACH DATABASE '{decrypted_db_file_path}' AS plaintext KEY '';")
                                cursor.execute("SELECT sqlcipher_export('plaintext');")
                                cursor.execute("DETACH DATABASE plaintext;")
                                conn.commit()
                                cursor.close()
                                conn.close()
                            except Exception as e:
                                print(e)
                                print(file_name + "解密失败！")
                            finally:
                                if conn:
                                    conn.close()
    print("解密结束，解密后的数据库文件在：", output_base_directory)

def unserial_message(messages):
    if messages is None:
        return "None"
    NEW_Message = QQ_Message_pb2.Message()
    NEW_Message.ParseFromString(messages)
    decoded_message = ''
    for SingleMessage in NEW_Message.messages:
        if SingleMessage.messageType == 1:
            decoded_message += " " + str(SingleMessage.messageText).replace("\r", "\\r") + " "
        elif SingleMessage.messageType == 2:
            if "gchatpic_new" in SingleMessage.imageUrlOrigin:
                decoded_message += " " + "http://gchat.qpic.cn" + SingleMessage.imageUrlOrigin + " "
            else:
                decoded_message += " [picture:" + SingleMessage.fileName + "] "
        elif SingleMessage.messageType == 3 or SingleMessage.messageType == 4 or SingleMessage.messageType == 5:
            decoded_message += " [fileName:" + SingleMessage.fileName + "] "
        elif SingleMessage.messageType == 6:
            if SingleMessage.emojiText != "":
                decoded_message += " [emoji:" + SingleMessage.emojiText + "] "
            else:
                if SingleMessage.emojiId in emoji.emoji.keys():
                    decoded_message += " [emoji:" + emoji.emoji[SingleMessage.emojiId] + "] "
                else:
                    decoded_message += " [未知emoji] "
        elif SingleMessage.messageType == 7:
            decoded_message += f" 回复{SingleMessage.senderUid}发布的'{SingleMessage.replyMessage.messageText}'消息： "
        elif SingleMessage.messageType == 8:
            if SingleMessage.noticeInfo != "":
                decoded_message += " " + SingleMessage.noticeInfo + " "
                if SingleMessage.noticeInfo2 != "":
                    decoded_message += " " + SingleMessage.noticeInfo2 + " "
            else:
                decoded_message += " [提示消息] "
        elif SingleMessage.messageType == 10:
            decoded_message += " " + SingleMessage.applicationMessage + " "
        elif SingleMessage.messageType == 11:
            decoded_message += " [表情包] "
        elif SingleMessage.messageType == 21:
            decoded_message += " [电话] "
        elif SingleMessage.messageType == 26:
            decoded_message += " [动态消息] "
    return decoded_message.strip()

def write_result_to_db_file(decrypted_db_file_path, decoded_db_file_path, table_name, qq_number):
    data = {}
    conn = None
    keywords = ["密码", "http", "拦截", "改机", "猫卡", "授权", "快手", "磁力", "美团", "大众", "点评", "接码", "团购", "评价", "评论", "撸货", "新奇", "数字人民币"]
    try:
        conn = sqlite.connect(decrypted_db_file_path)
        c = conn.cursor()
        cursor = c.execute(f"SELECT * from {table_name}")
        for row in cursor:
            sendtime = row[13]
            timeArray = time.localtime(sendtime)
            TimesTamp = time.strftime("%Y-%m-%d %H:%M:%S", timeArray)

            senderQQ = row[32]
            isSender = "1" if int(senderQQ) == int(qq_number) else "0"
            QQNickName = row[16]
            messages = row[17]
            decoded_msg = unserial_message(messages)
            if table_name == 'c2c_msg_table':
                otherQQ = row[31]
                if otherQQ not in data.keys():
                    data[otherQQ] = []
                data[otherQQ].append((TimesTamp, otherQQ, senderQQ, isSender, QQNickName, decoded_msg))
            elif table_name == 'group_msg_table':
                groupid = row[31]
                if groupid not in data.keys():
                    data[groupid] = []
                data[groupid].append((TimesTamp, groupid, senderQQ, isSender, QQNickName, decoded_msg))
    except Exception as e:
        print(e)
        print("nt_msg_decrypted.db 反序列化失败！")
    finally:
        if conn:
            conn.close()
    # 创建新的 SQLite 数据库（如果数据库已存在则连接到它）
    conn = sqlite.connect(decoded_db_file_path)

    # 创建一个 cursor 对象
    cursor = conn.cursor()
    if table_name == 'c2c_msg_table':
        for i in data.keys():
            cursor.execute(f'''CREATE TABLE "{i}" (
                                                TimesTamp TEXT,
                                                otherQQ TEXT,
                                                senderQQ TEXT,
                                                isSender TEXT,
                                                QQNickName TEXT,
                                                DecodedMSG TEXT
                                            )
                                            ''')
            cursor.executemany(f''' INSERT INTO "{i}" (TimesTamp, otherQQ, senderQQ, isSender, QQNickName, DecodedMSG) 
                                            VALUES (?, ?, ?, ?, ?, ?)
                                            ''', data[i])
            # 提交事务
            conn.commit()
            for keyword in keywords:
                for one_item in data[i]:
                    if keyword in one_item[5]:
                        cursor.execute(f'''CREATE TABLE IF NOT EXISTS 关键聊天记录 (
                                                                                            TimesTamp TEXT,
                                                                                            otherQQ TEXT,
                                                                                            senderQQ TEXT,
                                                                                            isSender TEXT,
                                                                                            QQNickName TEXT,
                                                                                            DecodedMSG TEXT
                                                                                        )''')
                        cursor.executemany(f'''INSERT INTO 关键聊天记录 (TimesTamp, otherQQ, senderQQ, isSender, QQNickName, DecodedMSG) 
                                                                                        VALUES (?, ?, ?, ?, ?, ?)
                                                                                        ''', [one_item])
                        conn.commit()
    elif table_name == 'group_msg_table':
        for i in data.keys():
            cursor.execute(f'''CREATE TABLE "{i}" (
                                                TimesTamp TEXT,
                                                GroupID TEXT,
                                                senderQQ TEXT,
                                                isSender TEXT,
                                                QQNickName TEXT,
                                                DecodedMSG TEXT
                                            )''')
            cursor.executemany(f'''INSERT INTO "{i}" (TimesTamp, GroupID, senderQQ, isSender, QQNickName, DecodedMSG) 
                                            VALUES (?, ?, ?, ?, ?, ?)
                                            ''', data[i])
            # 提交事务
            conn.commit()
            for keyword in keywords:
                for one_item in data[i]:
                    if keyword in one_item[5]:
                        cursor.execute(f'''CREATE TABLE IF NOT EXISTS 关键聊天记录 (
                                                                                            TimesTamp TEXT,
                                                                                            GroupID TEXT,
                                                                                            senderQQ TEXT,
                                                                                            isSender TEXT,
                                                                                            QQNickName TEXT,
                                                                                            DecodedMSG TEXT
                                                                                        )''')
                        cursor.executemany(f'''INSERT INTO 关键聊天记录 (TimesTamp, GroupID, senderQQ, isSender, QQNickName, DecodedMSG) 
                                                                                        VALUES (?, ?, ?, ?, ?, ?)
                                                                                        ''', [one_item])
                        conn.commit()
    # 关闭连接
    conn.close()

def generate_decoded_db_files(decrypted_db_path):
    output_base_directory = './decoded'
    for qq_number in os.listdir(decrypted_db_path):
        msg_db_directory = os.path.join(decrypted_db_path, qq_number, "nt_msg")
        if os.path.isdir(msg_db_directory):
            for file_name in os.listdir(msg_db_directory):
                if file_name == "nt_msg_decrypted.db":
                    output_dir = os.path.join(output_base_directory, qq_number)
                    os.makedirs(output_dir, exist_ok=True)
                    decoded_c2cdb_file_path = os.path.join(output_dir, 'c2c_nt_msg_decoded.db')
                    decoded_groupdb_file_path = os.path.join(output_dir, 'group_nt_msg_decoded.db')
                    decrypted_db_file_path = os.path.join(msg_db_directory, 'nt_msg_decrypted.db')
                    write_result_to_db_file(decrypted_db_file_path, decoded_c2cdb_file_path, 'c2c_msg_table', qq_number)
                    write_result_to_db_file(decrypted_db_file_path, decoded_groupdb_file_path, 'group_msg_table', qq_number)
    print('解码结束，解密后的数据库文件在: ', output_base_directory)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--path', type=str, help='指定清除无关头后的数据库路径')
    # 解析命令行参数
    args = parser.parse_args()
    decrypt_db_files(args.path)
    generate_decoded_db_files('./decrypted')

