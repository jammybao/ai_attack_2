#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
测试新版API的结构和返回值
"""
import requests
import json
import argparse
from pprint import pprint
from rich.console import Console
from rich.table import Table
from rich import box

def test_api_query(api_base_url, question):
    """测试API查询功能"""
    console = Console()
    
    console.print(f"[bold cyan]测试查询API[/]: {api_base_url}/query")
    console.print(f"[bold]查询问题[/]: {question}")
    
    try:
        # 发送查询请求
        response = requests.post(
            f"{api_base_url}/query",
            json={
                "question": question,
                "use_ml": True
            },
            timeout=60
        )
        
        # 检查响应状态
        if response.status_code != 200:
            console.print(f"[bold red]请求失败[/]: HTTP状态码 {response.status_code}")
            console.print(response.text)
            return None
        
        # 解析响应
        result = response.json()
        
        # 打印基本响应信息
        console.print("\n[bold green]请求成功[/]")
        console.print(f"[bold]SQL查询[/]: {result['sql_query']}")
        
        # 检查新增的AI洞察字段
        if "ai_insight" in result:
            console.print("\n[bold cyan]新增的AI洞察字段存在[/] ✓")
            ai_insight = result["ai_insight"]
            
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
        else:
            console.print("\n[bold red]新增的AI洞察字段不存在[/] ✗")
        
        return result
    
    except Exception as e:
        console.print(f"[bold red]测试失败[/]: {str(e)}")
        return None

def simulate_feishu_card(ai_insight):
    """模拟生成飞书卡片预览"""
    console = Console()
    
    console.print("\n[bold]飞书卡片预览[/]")
    
    # 创建飞书卡片边框
    console.print("┌" + "─" * 60 + "┐")
    
    # 卡片标题
    risk_level = ai_insight.get('risk_level', '未知')
    title_color = "red" if risk_level == "高" else ("yellow" if risk_level == "中" else "green")
    console.print(f"│ [bold {title_color}]安全预警 - 风险等级: {risk_level}[/]" + " " * (40 - len(risk_level)) + "│")
    console.print("├" + "─" * 60 + "┤")
    
    # 安全评分和攻击次数
    score = ai_insight.get('smart_score', 0)
    console.print(f"│ [bold]安全评分[/]: {score}/100" + " " * (46 - len(str(score))) + "│")
    
    attack_count = ai_insight.get('external_attack_count', 0)
    console.print(f"│ [bold]外部攻击次数[/]: {attack_count}" + " " * (44 - len(str(attack_count))) + "│")
    console.print("├" + "─" * 60 + "┤")
    
    # 高风险事件
    console.print(f"│ [bold]高风险事件[/]:" + " " * 46 + "│")
    
    high_risk_events = ai_insight.get('high_risk_events', [])
    if high_risk_events:
        for event in high_risk_events:
            ip = event.get('ip', '未知')
            description = event.get('description', '未知')
            event_type = event.get('event_type', '未知')
            
            # 裁剪过长的描述
            display_text = f"- {ip}: {description} [{event_type}]"
            if len(display_text) > 58:
                display_text = display_text[:55] + "..."
            
            console.print(f"│ {display_text}" + " " * (60 - len(display_text)) + "│")
    else:
        console.print("│ 无高风险事件" + " " * 46 + "│")
    
    # 预测攻击
    predicted_attacks = ai_insight.get('predicted_attacks', [])
    if predicted_attacks:
        console.print("├" + "─" * 60 + "┤")
        console.print(f"│ [bold]预测攻击[/]:" + " " * 47 + "│")
        
        for attack in predicted_attacks:
            target_ip = attack.get('target_ip', '未知')
            attack_type = attack.get('attack_type', '未知')
            probability = attack.get('probability', 0)
            
            display_text = f"- 目标 {target_ip}: {attack_type} (概率: {probability}%)"
            if len(display_text) > 58:
                display_text = display_text[:55] + "..."
            
            console.print(f"│ {display_text}" + " " * (60 - len(display_text)) + "│")
    
    # 卡片底部
    console.print("└" + "─" * 60 + "┘")

def export_to_json(data, filename):
    """将API响应导出为JSON文件"""
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        print(f"数据已导出到: {filename}")
        return True
    except Exception as e:
        print(f"导出失败: {str(e)}")
        return False

def main():
    """主函数"""
    parser = argparse.ArgumentParser(description="测试新版API结构")
    parser.add_argument("--url", default="http://localhost:8000/api/v1", help="API基础URL")
    parser.add_argument("--question", default="分析最近一周的网络攻击，重点关注高风险攻击和外部IP，评估风险等级", 
                      help="查询问题")
    parser.add_argument("--output", help="输出结果到JSON文件")
    
    args = parser.parse_args()
    
    # 测试API查询
    result = test_api_query(args.url, args.question)
    
    if result and "ai_insight" in result:
        # 模拟飞书卡片
        simulate_feishu_card(result["ai_insight"])
        
        # 导出结果
        if args.output:
            export_to_json(result, args.output)

if __name__ == "__main__":
    main() 