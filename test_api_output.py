#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
简化版的API测试脚本，专注于输出格式
"""
import requests
import json
from rich.console import Console
from rich.table import Table
from rich import box

# 发送查询
response = requests.post(
    "http://localhost:8000/api/v1/query",
    json={
        "question": "分析最近一周的网络攻击，重点关注高风险攻击和外部IP，评估风险等级",
        "use_ml": True
    },
    timeout=30
)

console = Console()

if response.status_code == 200:
    result = response.json()
    
    # 打印AI洞察
    if "ai_insight" in result:
        ai_insight = result["ai_insight"]
        
        # 创建洞察表格
        insight_table = Table(title="AI安全洞察", box=box.ROUNDED)
        insight_table.add_column("指标", style="cyan")
        insight_table.add_column("值", style="yellow")
        
        # 添加表格行
        insight_table.add_row("智能安全评分", f"{ai_insight.get('smart_score', 'N/A')}")
        insight_table.add_row("外部IP攻击次数", f"{ai_insight.get('external_attack_count', 0)}")
        insight_table.add_row("整体风险等级", f"{ai_insight.get('risk_level', '未知')}")
        
        # 打印表格
        console.print(insight_table)
        
        # 打印高风险事件
        high_risk_events = ai_insight.get("high_risk_events", [])
        if high_risk_events:
            console.print("\n[bold]高风险攻击事件:[/]")
            event_table = Table(box=box.SIMPLE)
            event_table.add_column("IP地址", style="cyan")
            event_table.add_column("风险等级", style="red")
            event_table.add_column("事件类型", style="yellow")
            event_table.add_column("描述", style="white")
            
            for event in high_risk_events:
                event_table.add_row(
                    event.get("ip", "未知"),
                    event.get("risk_level", "未知"),
                    event.get("event_type", "未知"),
                    event.get("description", "未知")
                )
            console.print(event_table)
        else:
            console.print("\n[yellow]没有高风险攻击事件[/]")
        
        # 打印预测攻击
        predicted_attacks = ai_insight.get("predicted_attacks", [])
        if predicted_attacks:
            console.print("\n[bold]预测攻击:[/]")
            attack_table = Table(box=box.SIMPLE)
            attack_table.add_column("目标IP", style="cyan")
            attack_table.add_column("攻击类型", style="yellow")
            attack_table.add_column("概率", style="red")
            attack_table.add_column("时间框架", style="white")
            
            for attack in predicted_attacks:
                attack_table.add_row(
                    attack.get("target_ip", "未知"),
                    attack.get("attack_type", "未知"),
                    f"{attack.get('probability', 0)}%",
                    attack.get("timeframe", "未知")
                )
            console.print(attack_table)
    else:
        console.print("[red]响应中没有AI洞察字段[/]")
else:
    console.print(f"[red]请求失败: {response.status_code}[/]")
    console.print(response.text) 