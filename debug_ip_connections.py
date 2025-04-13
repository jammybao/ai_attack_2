#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
调试IP连接和SQL查询的脚本
"""
import os
import sys
import pymysql
import pandas as pd
from datetime import datetime, timedelta
from dotenv import load_dotenv
import ipaddress

# 加载环境变量
load_dotenv()

# 数据库连接信息
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_USER = os.getenv("DB_USER", "root")
DB_PASSWORD = os.getenv("DB_PASSWORD", "password")
DB_NAME = os.getenv("DB_NAME", "itm")
DB_PORT = int(os.getenv("DB_PORT", "3306"))

# 定义私有IP地址范围
PRIVATE_IP_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),  # 本地回环
]

def is_private_ip(ip_str):
    """判断IP是否为私有IP"""
    try:
        ip = ipaddress.ip_address(ip_str)
        for cidr in PRIVATE_IP_RANGES:
            if ip in cidr:
                return True
        return False
    except ValueError:
        # 如果IP格式无效，返回False
        return False

def connect_to_database():
    """连接到数据库"""
    try:
        connection = pymysql.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME,
            port=DB_PORT,
            cursorclass=pymysql.cursors.DictCursor
        )
        print(f"成功连接到数据库: {DB_NAME}")
        return connection
    except Exception as e:
        print(f"数据库连接失败: {str(e)}")
        return None

def debug_sql_query(hours=168):
    """调试SQL查询及其结果"""
    # 连接数据库
    connection = connect_to_database()
    if not connection:
        return
    
    try:
        with connection.cursor() as cursor:
            # 1. 首先显示当前使用的查询
            end_time = datetime.now()
            start_time = end_time - timedelta(hours=hours)
            
            current_query = """
            SELECT 
                ids_ai.event_time, 
                ids_ai.src_ip, 
                ids_ai.dst_ip, 
                ids_ai.threat_level, 
                ids_ai.signature,
                ip_address.network_type,
                CASE WHEN ip_address.network_type IS NULL THEN 'external' ELSE 'internal' END AS ip_type
            FROM 
                ids_ai
            LEFT JOIN 
                ip_address ON ids_ai.src_ip = ip_address.ip
            WHERE 
                ids_ai.event_time >= %s
            ORDER BY 
                ids_ai.event_time DESC
            """
            
            print("\n=== 当前使用的SQL查询 ===")
            print(current_query)
            print(f"参数: {start_time}")
            
            # 2. 执行查询
            cursor.execute(current_query, (start_time,))
            
            # 3. 获取结果
            results = cursor.fetchall()
            
            print(f"\n查询到最近{hours}小时内{len(results)}条事件记录")
            
            # 4. 分析IP类型
            external_count_based_on_query = len([r for r in results if r['ip_type'] == 'external'])
            print(f"根据查询判断的外部IP连接数: {external_count_based_on_query}")
            
            # 5. 根据私有IP范围重新判断
            external_count_based_on_format = 0
            external_ips_list = []
            
            for record in results:
                src_ip = record['src_ip']
                current_ip_type = record['ip_type']
                is_private = is_private_ip(src_ip)
                
                formatted_ip_type = "internal" if is_private else "external"
                
                if formatted_ip_type == "external":
                    external_count_based_on_format += 1
                    
                    # 如果这个IP被标记为外部，但我们的判断不一致，记录下来
                    if current_ip_type != formatted_ip_type:
                        external_ips_list.append({
                            'ip': src_ip, 
                            'query_type': current_ip_type, 
                            'format_type': formatted_ip_type,
                            'network_type': record['network_type']
                        })
            
            print(f"根据IP格式判断的外部IP连接数: {external_count_based_on_format}")
            
            # 6. 检查ip_address表中所有数据
            cursor.execute("SELECT * FROM ip_address LIMIT 10")
            ip_address_records = cursor.fetchall()
            
            print("\n=== ip_address表中的前10条记录 ===")
            for record in ip_address_records:
                print(record)
            
            # 7. 显示网络类型的分布
            cursor.execute("SELECT network_type, COUNT(*) as count FROM ip_address GROUP BY network_type")
            network_types = cursor.fetchall()
            
            print("\n=== 网络类型分布 ===")
            for net_type in network_types:
                print(f"{net_type['network_type']}: {net_type['count']}条记录")
            
            # 8. 显示所有被查询判断为外部但格式是内部IP的记录
            print("\n=== 判断不一致的IP(查询判断为external但格式是internal) ===")
            for ip_info in external_ips_list:
                if ip_info['query_type'] == 'external' and ip_info['format_type'] == 'internal':
                    print(f"IP: {ip_info['ip']}, 查询判断: {ip_info['query_type']}, 格式判断: {ip_info['format_type']}, 网络类型: {ip_info['network_type']}")
            
            # 9. 显示所有外部IP的详细情况
            cursor.execute("""
            SELECT 
                ids_ai.src_ip, 
                COUNT(*) as event_count,
                ip_address.network_type
            FROM 
                ids_ai
            LEFT JOIN 
                ip_address ON ids_ai.src_ip = ip_address.ip
            WHERE 
                ids_ai.event_time >= %s
                AND (ip_address.network_type IS NULL)
            GROUP BY 
                ids_ai.src_ip, ip_address.network_type
            ORDER BY 
                event_count DESC
            """, (start_time,))
            
            external_details = cursor.fetchall()
            
            print("\n=== 查询判断为外部的IP详情 ===")
            for detail in external_details:
                ip = detail['src_ip']
                count = detail['event_count']
                network_type = detail['network_type']
                is_private = is_private_ip(ip)
                
                print(f"IP: {ip}, 事件数: {count}, 网络类型: {network_type}, 是否私有IP格式: {'是' if is_private else '否'}")
            
            # 10. 检查一些特定的外部IP记录
            if external_details:
                for i, detail in enumerate(external_details[:5]):
                    ip = detail['src_ip']
                    
                    print(f"\n=== 外部IP {ip} 的相关事件 ===")
                    cursor.execute("""
                    SELECT 
                        event_time, src_ip, dst_ip, threat_level, signature
                    FROM 
                        ids_ai
                    WHERE 
                        src_ip = %s
                        AND event_time >= %s
                    LIMIT 5
                    """, (ip, start_time))
                    
                    ip_events = cursor.fetchall()
                    for event in ip_events:
                        print(f"时间: {event['event_time']}, 源IP: {event['src_ip']}, 目标IP: {event['dst_ip']}, 威胁等级: {event['threat_level']}, 类型: {event['signature']}")
                
    except Exception as e:
        print(f"调试过程出错: {str(e)}")
        import traceback
        print(traceback.format_exc())
    finally:
        connection.close()
        print("\n数据库连接已关闭")

if __name__ == "__main__":
    hours = 168  # 默认查询一周
    if len(sys.argv) > 1:
        try:
            hours = int(sys.argv[1])
        except ValueError:
            print(f"无效的小时数: {sys.argv[1]}，使用默认值168")
    
    print(f"正在调试最近{hours}小时的数据...")
    debug_sql_query(hours) 