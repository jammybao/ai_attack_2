#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
专门测试从SQL结果中提取高风险事件
"""
import json
from pprint import pprint
from rich.console import Console
from rich.table import Table
from rich import box
import sys
import os

# 添加项目根目录到Python路径
sys.path.append(os.path.abspath('.'))

# 导入待测试的函数
from security_agent.api.routes import extract_ai_insight

def test_with_sql_result():
    """使用SQL查询结果直接测试高风险事件提取"""
    console = Console()
    console.print("[bold cyan]测试从SQL结果中提取高风险事件[/]")
    
    # 创建测试数据
    analysis = {
        "risk_level": "高",
        "key_findings": ["检测到网络攻击活动"]
    }
    
    # SQL查询
    sql_query = "SELECT `event_time`, `threat_level`, `category`, `src_ip`, `dst_ip`, `signature` FROM `ids_ai` WHERE threat_level >= 30 AND `event_time` >= CURDATE() - INTERVAL 7 DAY AND `threat_level` >= 30;"
    
    # 1. 测试元组格式的SQL结果
    sql_result_tuple = "[(datetime.datetime(2025, 3, 27, 9, 59, 17), 40, '可疑行为', '174.34.46.104', '10.0.0.5', 'TCP_可疑行为_SSH疑似爆破'), (datetime.datetime(2025, 3, 28, 14, 23, 5), 35, '漏洞利用', '103.25.58.34', '192.168.1.10', 'SQL注入攻击'), (datetime.datetime(2025, 3, 29, 3, 15, 42), 30, '网络扫描', '45.132.192.12', '10.0.0.6', '端口扫描')]"
    
    console.print("\n[bold]测试元组格式SQL结果...[/]")
    test_result(analysis, sql_query, sql_result_tuple, console)
    
    # 2. 测试JSON格式的SQL结果
    sql_result_json = json.dumps([
        {"event_time": "2025-03-27 09:59:17", "threat_level": 40, "category": "可疑行为", "src_ip": "174.34.46.104", "dst_ip": "10.0.0.5", "signature": "TCP_可疑行为_SSH疑似爆破"},
        {"event_time": "2025-03-28 14:23:05", "threat_level": 35, "category": "漏洞利用", "src_ip": "103.25.58.34", "dst_ip": "192.168.1.10", "signature": "SQL注入攻击"},
        {"event_time": "2025-03-29 03:15:42", "threat_level": 30, "category": "网络扫描", "src_ip": "45.132.192.12", "dst_ip": "10.0.0.6", "signature": "端口扫描"}
    ])
    
    console.print("\n[bold]测试JSON格式SQL结果...[/]")
    test_result(analysis, sql_query, sql_result_json, console)
    
    # 3. 测试表格格式的SQL结果
    sql_result_table = """
| event_time           | threat_level | category     | src_ip        | dst_ip        | signature                 |
|----------------------|--------------|--------------|---------------|---------------|---------------------------|
| 2025-03-27 09:59:17  | 40           | 可疑行为     | 174.34.46.104 | 10.0.0.5      | TCP_可疑行为_SSH疑似爆破   |
| 2025-03-28 14:23:05  | 35           | 漏洞利用     | 103.25.58.34  | 192.168.1.10  | SQL注入攻击               |
| 2025-03-29 03:15:42  | 30           | 网络扫描     | 45.132.192.12 | 10.0.0.6      | 端口扫描                  |
    """
    
    console.print("\n[bold]测试表格格式SQL结果...[/]")
    test_result(analysis, sql_query, sql_result_table, console)
    
    # 4. 测试中文威胁等级的SQL结果
    sql_result_chinese = json.dumps([
        {"event_time": "2025-03-27 09:59:17", "threat_level": "高", "category": "可疑行为", "src_ip": "174.34.46.104", "dst_ip": "10.0.0.5", "signature": "TCP_可疑行为_SSH疑似爆破"},
        {"event_time": "2025-03-28 14:23:05", "threat_level": "中", "category": "漏洞利用", "src_ip": "103.25.58.34", "dst_ip": "192.168.1.10", "signature": "SQL注入攻击"},
        {"event_time": "2025-03-29 03:15:42", "threat_level": "低", "category": "网络扫描", "src_ip": "45.132.192.12", "dst_ip": "10.0.0.6", "signature": "端口扫描"}
    ])
    
    console.print("\n[bold]测试中文威胁等级SQL结果...[/]")
    test_result(analysis, sql_query, sql_result_chinese, console)

def test_result(analysis, sql_query, sql_result, console):
    """测试从SQL结果中提取高风险事件"""
    try:
        # 调用待测试的函数
        ai_insight = extract_ai_insight(analysis, sql_query, sql_result)
        console.print("[bold green]函数调用成功[/] ✓")
        
        # 检查高风险事件
        high_risk_events = ai_insight.get("high_risk_events", [])
        
        if high_risk_events:
            console.print(f"[green]成功提取了{len(high_risk_events)}个高风险事件[/] ✓")
            
            # 打印高风险事件表格
            table = Table(box=box.SIMPLE)
            table.add_column("IP地址", style="cyan")
            table.add_column("风险等级", style="red")
            table.add_column("事件类型", style="yellow")
            table.add_column("描述", style="white")
            
            for event in high_risk_events:
                table.add_row(
                    event.get("ip", "未知"),
                    event.get("risk_level", "未知"),
                    event.get("event_type", "未知"),
                    event.get("description", "未知")
                )
            console.print(table)
        else:
            console.print("[bold red]没有提取到任何高风险事件[/] ✗")
            
        return ai_insight
    
    except Exception as e:
        console.print(f"[bold red]函数调用失败[/]: {str(e)}")
        import traceback
        console.print(traceback.format_exc())
        return None

if __name__ == "__main__":
    # 测试从SQL结果中提取高风险事件
    test_with_sql_result() 