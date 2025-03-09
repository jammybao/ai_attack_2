"""
数据库初始化工具
"""
import logging
from datetime import datetime, timedelta
import random
import pandas as pd
import numpy as np
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from security_agent.models.security_log import Base, SecurityLog
from security_agent.config import settings

logger = logging.getLogger(__name__)

def init_database():
    """初始化数据库"""
    # 创建数据库引擎
    engine = create_engine(settings.DB_CONNECTION_STRING)
    
    # 创建表
    Base.metadata.create_all(engine)
    logger.info("数据库表已创建")
    
    # 创建会话
    Session = sessionmaker(bind=engine)
    session = Session()
    
    # 检查是否已有数据
    log_count = session.query(SecurityLog).count()
    if log_count > 0:
        logger.info(f"数据库中已有 {log_count} 条记录，跳过示例数据生成")
        session.close()
        return
    
    # 生成示例数据
    logger.info("生成示例安全日志数据")
    generate_sample_data(engine)
    
    session.close()
    logger.info("数据库初始化完成")

def generate_sample_data(engine, num_records=1000):
    """生成示例安全日志数据"""
    # 定义可能的值
    source_ips = [f"192.168.1.{i}" for i in range(1, 50)] + [f"203.0.113.{i}" for i in range(1, 10)]
    dest_ips = [f"10.0.0.{i}" for i in range(1, 20)] + [f"172.16.0.{i}" for i in range(1, 5)]
    event_types = [
        "登录尝试", "登录成功", "登录失败", "权限提升", "文件访问", 
        "配置更改", "防火墙警报", "端口扫描", "恶意软件检测", "DDoS攻击"
    ]
    severities = ["低", "中", "高", "严重"]
    protocols = ["TCP", "UDP", "HTTP", "HTTPS", "SSH", "FTP", "SMTP"]
    actions = ["允许", "拒绝", "警告", "阻止", "记录"]
    statuses = ["成功", "失败", "超时", "中断"]
    user_ids = ["admin", "user1", "user2", "system", "guest", "root", "unknown"]
    
    # 生成时间范围
    end_time = datetime.now()
    start_time = end_time - timedelta(days=7)
    
    # 创建随机时间戳
    timestamps = [start_time + (end_time - start_time) * random.random() for _ in range(num_records)]
    timestamps.sort()
    
    # 创建数据框
    data = {
        "timestamp": timestamps,
        "source_ip": [random.choice(source_ips) for _ in range(num_records)],
        "destination_ip": [random.choice(dest_ips) for _ in range(num_records)],
        "event_type": [random.choice(event_types) for _ in range(num_records)],
        "severity": [random.choice(severities) for _ in range(num_records)],
        "protocol": [random.choice(protocols) for _ in range(num_records)],
        "source_port": [random.randint(1024, 65535) for _ in range(num_records)],
        "destination_port": [random.choice([22, 80, 443, 3306, 8080, 8443]) for _ in range(num_records)],
        "user_id": [random.choice(user_ids) for _ in range(num_records)],
        "action": [random.choice(actions) for _ in range(num_records)],
        "status": [random.choice(statuses) for _ in range(num_records)],
        "bytes_sent": [random.randint(100, 10000) for _ in range(num_records)],
        "bytes_received": [random.randint(100, 10000) for _ in range(num_records)],
        "session_duration": [random.randint(1, 3600) for _ in range(num_records)]
    }
    
    # 添加描述和原始日志
    descriptions = []
    raw_logs = []
    
    for i in range(num_records):
        event = data["event_type"][i]
        src_ip = data["source_ip"][i]
        dst_ip = data["destination_ip"][i]
        user = data["user_id"][i]
        action = data["action"][i]
        status = data["status"][i]
        
        description = f"{event}：来自 {src_ip} 的用户 {user} 尝试访问 {dst_ip}，{action}，{status}"
        descriptions.append(description)
        
        raw_log = (
            f"{data['timestamp'][i].strftime('%Y-%m-%d %H:%M:%S.%f')} "
            f"{data['protocol'][i]} {src_ip}:{data['source_port'][i]} -> "
            f"{dst_ip}:{data['destination_port'][i]} {event} {action} {status} "
            f"user={user} sent={data['bytes_sent'][i]} rcvd={data['bytes_received'][i]} "
            f"duration={data['session_duration'][i]}s"
        )
        raw_logs.append(raw_log)
    
    data["description"] = descriptions
    data["raw_log"] = raw_logs
    
    # 创建DataFrame
    df = pd.DataFrame(data)
    
    # 写入数据库
    df.to_sql("security_logs", engine, if_exists="append", index=False)
    logger.info(f"已生成 {num_records} 条示例安全日志数据")
    
    # 添加一些可疑活动
    generate_suspicious_activities(engine)

def generate_suspicious_activities(engine):
    """生成一些可疑活动的日志"""
    # 定义可疑活动
    suspicious_activities = [
        {
            "name": "端口扫描",
            "count": 50,
            "source_ip": "203.0.113.42",
            "event_type": "端口扫描",
            "severity": "中",
            "protocol": "TCP",
            "ports": [22, 23, 80, 443, 3389, 8080]
        },
        {
            "name": "暴力破解",
            "count": 30,
            "source_ip": "203.0.113.37",
            "event_type": "登录失败",
            "severity": "高",
            "protocol": "SSH",
            "user_id": "root"
        },
        {
            "name": "数据外泄",
            "count": 5,
            "source_ip": "192.168.1.25",
            "destination_ip": "198.51.100.23",
            "event_type": "文件访问",
            "severity": "严重",
            "protocol": "FTP",
            "bytes_sent": [50000, 100000]
        }
    ]
    
    # 生成可疑活动日志
    end_time = datetime.now()
    
    for activity in suspicious_activities:
        # 创建数据框
        records = []
        
        for i in range(activity["count"]):
            timestamp = end_time - timedelta(hours=random.randint(1, 8))
            
            record = {
                "timestamp": timestamp,
                "source_ip": activity["source_ip"],
                "destination_ip": activity.get("destination_ip", f"10.0.0.{random.randint(1, 20)}"),
                "event_type": activity["event_type"],
                "severity": activity["severity"],
                "protocol": activity["protocol"],
                "source_port": random.randint(1024, 65535),
                "user_id": activity.get("user_id", "unknown"),
                "action": "拒绝" if random.random() > 0.3 else "允许",
                "status": "失败" if random.random() > 0.3 else "成功",
            }
            
            if "ports" in activity:
                record["destination_port"] = random.choice(activity["ports"])
            else:
                record["destination_port"] = random.choice([22, 80, 443, 3306, 8080])
            
            if "bytes_sent" in activity:
                record["bytes_sent"] = random.randint(activity["bytes_sent"][0], activity["bytes_sent"][1])
                record["bytes_received"] = random.randint(100, 1000)
            else:
                record["bytes_sent"] = random.randint(100, 10000)
                record["bytes_received"] = random.randint(100, 10000)
            
            record["session_duration"] = random.randint(1, 60)
            
            # 添加描述和原始日志
            description = f"{record['event_type']}：来自 {record['source_ip']} 的用户 {record['user_id']} 尝试访问 {record['destination_ip']}，{record['action']}，{record['status']}"
            record["description"] = description
            
            raw_log = (
                f"{record['timestamp'].strftime('%Y-%m-%d %H:%M:%S.%f')} "
                f"{record['protocol']} {record['source_ip']}:{record['source_port']} -> "
                f"{record['destination_ip']}:{record['destination_port']} {record['event_type']} {record['action']} {record['status']} "
                f"user={record['user_id']} sent={record['bytes_sent']} rcvd={record['bytes_received']} "
                f"duration={record['session_duration']}s"
            )
            record["raw_log"] = raw_log
            
            records.append(record)
        
        # 创建DataFrame并写入数据库
        df = pd.DataFrame(records)
        df.to_sql("security_logs", engine, if_exists="append", index=False)
        logger.info(f"已生成 {activity['count']} 条 {activity['name']} 可疑活动日志") 