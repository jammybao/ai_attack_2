#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
直接测试extract_ai_insight函数，不依赖API服务
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

def test_with_example_response():
    """使用示例响应数据测试extract_ai_insight函数"""
    console = Console()
    console.print("[bold cyan]直接测试extract_ai_insight函数[/]")
    
    # 加载示例响应
    try:
        with open('example_response.json', 'r', encoding='utf-8') as f:
            example_data = json.load(f)
        console.print("[green]成功加载示例响应数据[/]")
    except Exception as e:
        console.print(f"[bold red]加载示例响应失败[/]: {str(e)}")
        return
    
    # 准备测试数据
    analysis = example_data.get('security_analysis', {})
    sql_query = example_data.get('sql_query', '')
    sql_result = example_data.get('sql_result', '')
    
    console.print(f"[bold]SQL查询[/]: {sql_query[:100]}...")
    
    # 调用待测试的函数
    try:
        console.print("\n[bold]测试extract_ai_insight函数...[/]")
        ai_insight = extract_ai_insight(analysis, sql_query, sql_result)
        console.print("[bold green]函数调用成功[/] ✓")
        
        # 打印结果
        console.print("\n[bold cyan]AI洞察结果[/]:")
        
        # 打印智能打分和攻击次数
        console.print(f"[bold]智能打分[/]: {ai_insight.get('smart_score', 'N/A')}")
        console.print(f"[bold]外部IP攻击次数[/]: {ai_insight.get('external_attack_count', 'N/A')}")
        console.print(f"[bold]风险等级[/]: {ai_insight.get('risk_level', 'N/A')}")
        
        # 打印高风险事件表格
        high_risk_events = ai_insight.get("high_risk_events", [])
        if high_risk_events:
            console.print("\n[bold]高风险攻击事件[/]:")
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
            console.print("[yellow]无高风险攻击事件[/]")
        
        # 打印预测攻击表格
        predicted_attacks = ai_insight.get("predicted_attacks", [])
        if predicted_attacks:
            console.print("\n[bold]预测攻击[/]:")
            table = Table(box=box.SIMPLE)
            table.add_column("目标IP", style="cyan")
            table.add_column("攻击类型", style="magenta")
            table.add_column("概率(%)", style="yellow")
            table.add_column("时间范围", style="white")
            
            for attack in predicted_attacks:
                table.add_row(
                    attack.get("target_ip", "未知"),
                    attack.get("attack_type", "未知"),
                    str(attack.get("probability", 0)),
                    attack.get("timeframe", "未知")
                )
            console.print(table)
        else:
            console.print("[yellow]无预测攻击[/]")
        
        # 验证数据完整性
        validate_results(ai_insight, console)
        
        # 返回结果
        return ai_insight
    
    except Exception as e:
        console.print(f"[bold red]函数调用失败[/]: {str(e)}")
        import traceback
        console.print(traceback.format_exc())
        return None

def validate_results(ai_insight, console):
    """验证AI洞察结果的完整性和正确性"""
    console.print("\n[bold]验证AI洞察结果[/]:")
    
    # 检查必要字段是否存在
    required_fields = [
        "smart_score", "external_attack_count", "high_risk_events", 
        "predicted_attacks", "risk_level"
    ]
    
    missing_fields = [field for field in required_fields if field not in ai_insight]
    
    if missing_fields:
        console.print(f"[bold red]缺少必要字段[/]: {', '.join(missing_fields)}")
    else:
        console.print("[green]所有必要字段均存在[/] ✓")
    
    # 验证智能打分在合理范围内(0-100)
    smart_score = ai_insight.get("smart_score", 0)
    if 0 <= smart_score <= 100:
        console.print(f"[green]智能打分在合理范围内: {smart_score}[/] ✓")
    else:
        console.print(f"[bold red]智能打分超出合理范围: {smart_score}[/]")
    
    # 验证外部IP攻击次数 >= 0
    external_attack_count = ai_insight.get("external_attack_count", 0)
    if external_attack_count >= 0:
        console.print(f"[green]外部IP攻击次数正确: {external_attack_count}[/] ✓")
    else:
        console.print(f"[bold red]外部IP攻击次数错误: {external_attack_count}[/]")
    
    # 检查高风险事件中的IP格式
    valid_ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    
    import re
    for i, event in enumerate(ai_insight.get("high_risk_events", [])):
        ip = event.get("ip", "")
        if ip != "未知" and not re.match(valid_ip_pattern, ip):
            console.print(f"[bold red]第{i+1}个高风险事件IP格式错误: {ip}[/]")
    
    # 验证预测攻击中的概率在合理范围内(0-100)
    for i, attack in enumerate(ai_insight.get("predicted_attacks", [])):
        probability = attack.get("probability", 0)
        if not (0 <= probability <= 100):
            console.print(f"[bold red]第{i+1}个预测攻击概率超出合理范围: {probability}[/]")
    
    console.print("[green]验证完成[/]")

def test_with_custom_data():
    """使用自定义数据测试extract_ai_insight函数"""
    console = Console()
    console.print("\n[bold cyan]使用自定义数据测试extract_ai_insight函数[/]")
    
    # 构造测试数据
    analysis = {
        "risk_level": "高",
        "key_findings": [
            "发现3个外部IP对内网服务器发起高频率连接",
            "检测到疑似SQL注入攻击",
            "服务器192.168.10.5接收到多次漏洞利用尝试"
        ],
        "recommendations": [
            "立即隔离受影响服务器",
            "更新Web应用防火墙规则",
            "进行应急响应处理"
        ],
        "ip_analysis": "分析发现10个IP地址，其中唯一IP有5个。\n- 内部IP: 2个\n  * 192.168.10.5 (网络类型: 办公网)\n  * 10.0.0.10 (网络类型: 服务器网)\n- 外部IP: 3个\n  * 45.67.89.12\n  * 123.45.67.89\n  * 98.76.54.32",
        "detailed_analysis": "在过去24小时内检测到多次高风险攻击事件，主要来自外部IP，针对内部Web服务器，攻击手段包括SQL注入和远程命令执行。"
    }
    
    # 模拟SQL查询和结果
    sql_query = "SELECT event_time, src_ip, dst_ip, threat_level, attack_function, signature, src_network_type FROM security_events WHERE event_time >= NOW() - INTERVAL 24 HOUR AND threat_level >= 30"
    
    sql_result = json.dumps([
        {"event_time": "2025-03-01 12:00:00", "src_ip": "45.67.89.12", "dst_ip": "192.168.10.5", 
         "threat_level": 40, "attack_function": "SQL注入", "signature": "SQL语法攻击模式检测", 
         "src_network_type": None},
        {"event_time": "2025-03-01 12:15:00", "src_ip": "123.45.67.89", "dst_ip": "192.168.10.5", 
         "threat_level": 35, "attack_function": "命令执行", "signature": "远程命令执行尝试", 
         "src_network_type": None},
        {"event_time": "2025-03-01 12:30:00", "src_ip": "98.76.54.32", "dst_ip": "10.0.0.10", 
         "threat_level": 30, "attack_function": "暴力破解", "signature": "SSH登录尝试次数过多", 
         "src_network_type": None}
    ])
    
    try:
        # 调用待测试的函数
        ai_insight = extract_ai_insight(analysis, sql_query, sql_result)
        console.print("[bold green]函数调用成功[/] ✓")
        
        # 打印结果
        console.print("\n[bold cyan]自定义数据的AI洞察结果[/]:")
        
        console.print(f"[bold]智能打分[/]: {ai_insight.get('smart_score', 'N/A')}")
        console.print(f"[bold]外部IP攻击次数[/]: {ai_insight.get('external_attack_count', 'N/A')}")
        console.print(f"[bold]风险等级[/]: {ai_insight.get('risk_level', 'N/A')}")
        
        # 打印高风险事件
        high_risk_events = ai_insight.get("high_risk_events", [])
        if high_risk_events:
            console.print("\n[bold]高风险攻击事件[/]:")
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
            
            # 验证从SQL结果中提取的高风险事件
            sql_ips = ["45.67.89.12", "123.45.67.89", "98.76.54.32"]
            found_ips = [event.get("ip") for event in high_risk_events]
            
            # 检查SQL结果中的IP是否被识别为高风险事件
            for ip in sql_ips:
                if ip in found_ips:
                    console.print(f"[green]成功从SQL结果中识别高风险IP: {ip}[/] ✓")
                else:
                    console.print(f"[bold red]未能从SQL结果中识别高风险IP: {ip}[/]")
        
        # 打印预测攻击
        predicted_attacks = ai_insight.get("predicted_attacks", [])
        if predicted_attacks:
            console.print("\n[bold]预测攻击[/]:")
            table = Table(box=box.SIMPLE)
            table.add_column("目标IP", style="cyan")
            table.add_column("攻击类型", style="magenta")
            table.add_column("概率(%)", style="yellow")
            table.add_column("时间范围", style="white")
            
            for attack in predicted_attacks:
                table.add_row(
                    attack.get("target_ip", "未知"),
                    attack.get("attack_type", "未知"),
                    str(attack.get("probability", 0)),
                    attack.get("timeframe", "未知")
                )
            console.print(table)
            
        # 验证数据完整性
        validate_results(ai_insight, console)
        
        return ai_insight
    
    except Exception as e:
        console.print(f"[bold red]函数调用失败[/]: {str(e)}")
        import traceback
        console.print(traceback.format_exc())
        return None

if __name__ == "__main__":
    # 使用示例响应数据测试
    test_with_example_response()
    
    # 使用自定义数据测试
    test_with_custom_data() 