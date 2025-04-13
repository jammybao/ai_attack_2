#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
数据库验证脚本 - 检查最近一周是否存在高风险事件
"""
import pymysql
import os
import json
from datetime import datetime, timedelta
from dotenv import load_dotenv

# 加载环境变量
load_dotenv()

# 数据库连接信息 - 从环境变量获取或使用默认值
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_USER = os.getenv("DB_USER", "root")
DB_PASSWORD = os.getenv("DB_PASSWORD", "password")
DB_NAME = os.getenv("DB_NAME", "security_db")
DB_PORT = int(os.getenv("DB_PORT", "3306"))

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

def query_high_risk_events(connection, days=7, threat_level_threshold=30):
    """查询最近指定天数内的高风险事件
    
    Args:
        connection: 数据库连接
        days: 查询的天数范围
        threat_level_threshold: 高风险阈值
        
    Returns:
        查询结果
    """
    try:
        with connection.cursor() as cursor:
            # 构建SQL查询 - 不使用LIMIT
            sql = """
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
                ids_ai.threat_level >= %s AND
                ids_ai.event_time >= DATE_SUB(CURDATE(), INTERVAL %s DAY)
            ORDER BY 
                ids_ai.event_time DESC
            """
            
            # 执行查询
            cursor.execute(sql, (threat_level_threshold, days))
            
            # 获取结果
            results = cursor.fetchall()
            print(f"查询到 {len(results)} 条threat_level >= {threat_level_threshold}的事件记录")
            
            return results
    except Exception as e:
        print(f"查询失败: {str(e)}")
        return []

def analyze_events(events):
    """分析事件数据
    
    Args:
        events: 事件记录列表
    """
    if not events:
        print("没有找到任何高风险事件记录")
        return
    
    # 统计内部和外部IP
    internal_ips = set()
    external_ips = set()
    
    for event in events:
        ip = event['src_ip']
        ip_type = event['ip_type']
        
        if ip_type == 'internal':
            internal_ips.add(ip)
        else:
            external_ips.add(ip)
    
    # 统计每天的事件数量
    daily_counts = {}
    for event in events:
        event_date = event['event_time'].strftime('%Y-%m-%d')
        if event_date not in daily_counts:
            daily_counts[event_date] = 0
        daily_counts[event_date] += 1
    
    # 打印分析结果
    print("\n事件分析:")
    print(f"总事件数: {len(events)}")
    print(f"内部IP数量: {len(internal_ips)}")
    print(f"外部IP数量: {len(external_ips)}")
    
    print("\n每日事件分布:")
    for date, count in sorted(daily_counts.items()):
        print(f"  {date}: {count}个事件")
    
    # 打印前5条记录示例
    print("\n记录样本(前5条):")
    for i, event in enumerate(events[:5]):
        print(f"{i+1}. 时间: {event['event_time']}, IP: {event['src_ip']} -> {event['dst_ip']}, " + 
              f"威胁等级: {event['threat_level']}, 类型: {event['signature']}, " +
              f"IP类型: {event['ip_type']}")

def save_results_to_file(events, filename="database_verification_results.json"):
    """将结果保存到文件
    
    Args:
        events: 事件记录列表
        filename: 输出文件名
    """
    # 转换datetime对象为字符串以便JSON序列化
    serializable_events = []
    for event in events:
        serialized_event = {**event}
        if isinstance(event['event_time'], datetime):
            serialized_event['event_time'] = event['event_time'].isoformat()
        serializable_events.append(serialized_event)
    
    # 保存为JSON文件
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump({
            "total_count": len(events),
            "timestamp": datetime.now().isoformat(),
            "events": serializable_events
        }, f, ensure_ascii=False, indent=2)
    
    print(f"\n结果已保存至: {filename}")

def main():
    """主函数"""
    # 连接数据库
    connection = connect_to_database()
    if not connection:
        return
    
    try:
        # 查询高风险事件 - 默认阈值30
        print("查询threat_level >= 30的高风险事件...")
        high_risk_events = query_high_risk_events(connection, days=7, threat_level_threshold=30)
        
        # 分析事件
        analyze_events(high_risk_events)
        
        # 保存结果
        save_results_to_file(high_risk_events)
        
        # 尝试查询更高阈值的事件
        print("\n\n查询threat_level >= 40的更高风险事件...")
        very_high_risk_events = query_high_risk_events(connection, days=7, threat_level_threshold=40)
        analyze_events(very_high_risk_events)
        
        # 扩大时间范围查询
        print("\n\n扩大查询范围 - 查询最近30天的高风险事件...")
        extended_period_events = query_high_risk_events(connection, days=30, threat_level_threshold=30)
        analyze_events(extended_period_events)
        
    finally:
        connection.close()
        print("\n数据库连接已关闭")

if __name__ == "__main__":
    main() 