'''
Description: 网络安全AI代理API接口的增强测试脚本
version: 1.0
Author: Claude
Date: 2025-04-03
LastEditTime: 2025-04-14 01:31:43
FilePath: \test_api_call_enhanced.py
'''
#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
增强版安全代理API测试脚本
- 支持命令行参数
- 支持多种查询模板
- 更好的错误处理
- 彩色输出
- 支持结果保存到文件
"""
import requests
import json
import re
import ast
import argparse
import sys
import time
from datetime import datetime
from typing import Dict, Any, List, Optional, Union

# 尝试导入rich库以支持彩色输出
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
    HAS_RICH = True
except ImportError:
    HAS_RICH = False
    print("提示: 安装rich库可以获得更好的输出体验: pip install rich")

# 全局变量
DEFAULT_API_URL = "http://localhost:8000/api/v1/query"
DEFAULT_TIMEOUT = 30

# 预定义查询模板
QUERY_TEMPLATES = {
    "high_risk": "分析最近一周的网络攻击，重点关注高风险攻击和外部IP，评估风险等级",
    "login_failures": "检查最近24小时的登录失败记录，分析是否存在暴力破解攻击",
    "external_ips": "统计最近3天来自外部IP的所有连接，识别可疑IP并评估风险",
    "malware": "检查最近一周是否有恶意软件感染迹象，分析受影响的主机",
    "port_scan": "分析最近48小时内的端口扫描活动，识别扫描源IP和扫描目标",
    "data_exfiltration": "检查是否有大量数据传输到外部IP，评估是否存在数据泄露风险",
    "privilege_escalation": "分析最近一周的权限提升事件，评估影响范围和安全风险",
    "lateral_movement": "检查内网中是否存在横向移动的迹象，识别可能被入侵的主机"
}

def setup_console() -> Union[Console, None]:
    """设置Rich控制台"""
    if HAS_RICH:
        return Console()
    return None

def parse_arguments() -> argparse.Namespace:
    """解析命令行参数"""
    parser = argparse.ArgumentParser(description="网络安全AI代理API测试工具")
    
    # 基本参数
    parser.add_argument("--url", default=DEFAULT_API_URL, help=f"API端点URL (默认: {DEFAULT_API_URL})")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help=f"请求超时时间(秒) (默认: {DEFAULT_TIMEOUT})")
    parser.add_argument("--save", metavar="FILENAME", help="保存结果到指定文件")
    
    # 查询相关参数
    query_group = parser.add_argument_group("查询选项")
    query_group.add_argument("--question", "-q", help="自定义查询问题")
    query_group.add_argument("--template", "-t", choices=list(QUERY_TEMPLATES.keys()), 
                            help="使用预定义查询模板")
    query_group.add_argument("--no-ml", action="store_true", help="禁用机器学习增强分析")
    
    # 输出选项
    output_group = parser.add_argument_group("输出选项")
    output_group.add_argument("--compact", action="store_true", help="使用紧凑输出格式")
    output_group.add_argument("--json-only", action="store_true", help="仅输出JSON格式结果")
    output_group.add_argument("--insights-only", action="store_true", help="仅显示AI洞察结果")
    
    # 调试选项
    debug_group = parser.add_argument_group("调试选项")
    debug_group.add_argument("--verbose", "-v", action="store_true", help="显示详细输出")
    debug_group.add_argument("--list-templates", action="store_true", help="列出所有预定义查询模板")
    
    args = parser.parse_args()
    
    # 如果指定了--list-templates，打印所有模板并退出
    if args.list_templates:
        print("可用的查询模板:")
        for key, value in QUERY_TEMPLATES.items():
            print(f"  {key}: {value}")
        sys.exit(0)
    
    # 验证查询参数
    if not args.question and not args.template:
        args.template = "high_risk"  # 默认使用高风险查询模板
    
    return args

def get_query_question(args: argparse.Namespace) -> str:
    """获取查询问题"""
    if args.question:
        return args.question
    elif args.template:
        return QUERY_TEMPLATES[args.template]
    return QUERY_TEMPLATES["high_risk"]  # 默认

def send_api_request(url: str, question: str, use_ml: bool, timeout: int) -> Dict[str, Any]:
    """发送API请求并返回结果"""
    try:
        start_time = time.time()
        response = requests.post(
            url,
            json={
                "question": question,
                "use_ml": use_ml
            },
            timeout=timeout
        )
        end_time = time.time()
        
        # 检查响应
        response.raise_for_status()  # 抛出HTTP错误
        result = response.json()
        result["_meta"] = {
            "request_time": end_time - start_time,
            "status_code": response.status_code,
            "timestamp": datetime.now().isoformat()
        }
        return result
    except requests.exceptions.HTTPError as e:
        print(f"HTTP错误: {e}")
        if response and response.text:
            print(f"响应内容: {response.text}")
        sys.exit(1)
    except requests.exceptions.ConnectionError:
        print(f"连接错误: 无法连接到API服务器 {url}")
        print("请确保API服务正在运行")
        sys.exit(1)
    except requests.exceptions.Timeout:
        print(f"超时错误: 请求超过了{timeout}秒")
        sys.exit(1)
    except requests.exceptions.RequestException as e:
        print(f"请求错误: {e}")
        sys.exit(1)
    except json.JSONDecodeError:
        print("错误: 无法解析API响应为JSON")
        if response and response.text:
            print(f"响应内容: {response.text[:500]}")
        sys.exit(1)

def print_standard_output(result: Dict[str, Any], args: argparse.Namespace, console: Optional[Console] = None):
    """打印标准输出格式"""
    meta = result.get("_meta", {})
    request_time = meta.get("request_time", 0)
    
    if console:
        # Rich彩色输出
        console.print(f"[bold green]状态码:[/] {meta.get('status_code', 'N/A')}")
        console.print(f"[bold green]请求耗时:[/] {request_time:.2f}秒")
        
        if not args.insights_only:
            # 显示SQL查询
            sql_query = result.get("sql_query", "未找到SQL查询")
            console.print(Panel(sql_query, title="[bold cyan]执行的SQL查询[/]", expand=False))
            
            # 显示SQL结果(部分)
            sql_result = result.get("sql_result", "未找到SQL结果")
            console.print(Panel(
                sql_result[:500] + ("..." if len(str(sql_result)) > 500 else ""), 
                title="[bold cyan]SQL查询结果(摘要)[/]", 
                expand=False
            ))
            
            # 显示回答
            formatted_answer = result.get("formatted_answer", "")
            if formatted_answer:
                console.print(Panel(formatted_answer, title="[bold cyan]安全分析结果[/]", expand=False))
        
        # 显示AI洞察
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
            
            # 高风险事件表格
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
            
            # 预测攻击表格
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
        # 普通文本输出
        print(f"状态码: {meta.get('status_code', 'N/A')}")
        print(f"请求耗时: {request_time:.2f}秒")
        
        if not args.insights_only:
            print("\n执行的SQL查询:")
            print(result.get("sql_query", "未找到SQL查询"))
            
            print("\nSQL查询结果(摘要):")
            sql_result = result.get("sql_result", "未找到SQL结果")
            print(f"{sql_result[:500]}..." if len(str(sql_result)) > 500 else sql_result)
            
            print("\n安全分析结果:")
            print(result.get("formatted_answer", "未找到分析结果"))
        
        if "ai_insight" in result:
            ai_insight = result["ai_insight"]
            
            print("\nAI安全洞察:")
            print(f"智能安全评分: {ai_insight.get('smart_score', 'N/A')}")
            print(f"外部IP攻击次数: {ai_insight.get('external_attack_count', 0)}")
            print(f"整体风险等级: {ai_insight.get('risk_level', '未知')}")
            
            high_risk_events = ai_insight.get("high_risk_events", [])
            if high_risk_events:
                print("\n高风险攻击事件:")
                for event in high_risk_events:
                    print(f"  - IP: {event.get('ip', '未知')}, 风险: {event.get('risk_level', '未知')}, "
                          f"类型: {event.get('event_type', '未知')}, 描述: {event.get('description', '未知')}")
            else:
                print("\n没有高风险攻击事件")
            
            predicted_attacks = ai_insight.get("predicted_attacks", [])
            if predicted_attacks:
                print("\n预测攻击:")
                for attack in predicted_attacks:
                    print(f"  - 目标IP: {attack.get('target_ip', '未知')}, 类型: {attack.get('attack_type', '未知')}, "
                          f"概率: {attack.get('probability', 0)}%, 时间框架: {attack.get('timeframe', '未知')}")

def save_results_to_file(result: Dict[str, Any], filename: str):
    """保存结果到文件"""
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        print(f"结果已保存到: {filename}")
    except IOError as e:
        print(f"保存结果失败: {e}")

def main():
    """主函数"""
    # 解析命令行参数
    args = parse_arguments()
    
    # 设置控制台
    console = setup_console() if not args.json_only else None
    
    # 获取查询问题
    question = get_query_question(args)
    
    # 发送API请求
    if console and not args.json_only:
        console.print(f"[bold]发送查询:[/] {question}")
        console.print(f"[bold]API URL:[/] {args.url}")
        console.print(f"[bold]使用机器学习:[/] {'否' if args.no_ml else '是'}")
    elif not args.json_only:
        print(f"发送查询: {question}")
        print(f"API URL: {args.url}")
        print(f"使用机器学习: {'否' if args.no_ml else '是'}")
    
    result = send_api_request(args.url, question, not args.no_ml, args.timeout)
    
    # 输出结果
    if args.json_only:
        # 只输出JSON结果
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        # 根据参数输出格式化结果
        print_standard_output(result, args, console)
    
    # 保存结果到文件
    if args.save:
        save_results_to_file(result, args.save)

if __name__ == "__main__":
    main() 