#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
自动化网络安全巡检脚本

功能：
1. 定时调用安全API
2. 根据API响应生成安全巡检报告
3. 保存历史巡检结果
4. 发送安全提醒(如有高风险事件)
"""
import os
import sys
import json
import time
import logging
import argparse
import schedule
import requests
from datetime import datetime, timedelta
from pathlib import Path
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("auto_inspection.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("auto_inspection")

# 全局配置
API_URL = "http://localhost:8000/api/v1/query"
REPORTS_DIR = "security_reports"
DEFAULT_INTERVAL_HOURS = 1
EMAIL_CONFIG = {
    "enabled": False,
    "smtp_server": "smtp.example.com",
    "smtp_port": 587,
    "username": "security@example.com",
    "password": "your_password",
    "from_email": "security@example.com",
    "to_emails": ["admin@example.com"]
}

# 确保报告目录存在
Path(REPORTS_DIR).mkdir(exist_ok=True)

def parse_arguments():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(description="自动化网络安全巡检工具")
    parser.add_argument("--interval", type=int, default=DEFAULT_INTERVAL_HOURS, 
                        help=f"巡检间隔时间(小时)，默认为{DEFAULT_INTERVAL_HOURS}小时")
    parser.add_argument("--run-now", action="store_true", help="立即运行一次巡检，不等待定时")
    parser.add_argument("--email", action="store_true", help="启用电子邮件通知")
    parser.add_argument("--recipients", help="电子邮件收件人，多个收件人用逗号分隔")
    
    return parser.parse_args()

def run_security_inspection():
    """执行安全巡检"""
    logger.info("开始执行安全巡检...")
    
    # 生成时间范围
    now = datetime.now()
    time_range = f"最近{DEFAULT_INTERVAL_HOURS}小时"
    
    # 构造查询
    query = f"分析{time_range}的网络攻击，重点关注高风险攻击和外部IP，评估风险等级"
    
    # 调用API
    try:
        response = requests.post(
            API_URL,
            json={"question": query, "use_ml": True},
            timeout=60
        )
        
        if response.status_code != 200:
            logger.error(f"API请求失败: HTTP {response.status_code}")
            logger.error(response.text)
            return None
            
        result = response.json()
        
        # 保存结果
        timestamp = now.strftime("%Y%m%d_%H%M%S")
        filename = f"{REPORTS_DIR}/security_report_{timestamp}.json"
        
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
            
        logger.info(f"安全巡检报告已保存至 {filename}")
        
        # 检查是否需要发送邮件通知
        risk_level = result.get("ai_insight", {}).get("risk_level", "")
        if EMAIL_CONFIG["enabled"] and risk_level == "高":
            send_alert_email(result, time_range)
            
        # 显示摘要
        print_inspection_summary(result, time_range)
        
        return result
        
    except Exception as e:
        logger.error(f"执行安全巡检时出错: {str(e)}")
        return None

def print_inspection_summary(result, time_range):
    """打印巡检摘要"""
    try:
        # 检查是否有Rich库
        console = Console()
        
        # 提取关键信息
        risk_level = result.get("ai_insight", {}).get("risk_level", "未知")
        smart_score = result.get("ai_insight", {}).get("smart_score", 0)
        external_attack_count = result.get("ai_insight", {}).get("external_attack_count", 0)
        high_risk_events = result.get("ai_insight", {}).get("high_risk_events", [])
        predicted_attacks = result.get("ai_insight", {}).get("predicted_attacks", [])
        
        # 设置风险级别的颜色
        risk_color = "green"
        if risk_level == "中":
            risk_color = "yellow"
        elif risk_level == "高":
            risk_color = "red"
            
        # 打印标题
        console.print(f"\n[bold]网络安全巡检报告 - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/]")
        console.print(f"[bold]巡检范围:[/] {time_range}")
        
        # 打印摘要
        summary_table = Table(title="安全摘要")
        summary_table.add_column("指标", style="cyan")
        summary_table.add_column("值", style="yellow")
        
        summary_table.add_row("风险等级", f"[{risk_color}]{risk_level}[/{risk_color}]")
        summary_table.add_row("安全评分", f"{smart_score}")
        summary_table.add_row("外部攻击次数", f"{external_attack_count}")
        summary_table.add_row("高风险事件数量", f"{len(high_risk_events)}")
        
        console.print(summary_table)
        
        # 打印高风险事件
        if high_risk_events:
            console.print("\n[bold]高风险事件:[/]")
            events_table = Table()
            events_table.add_column("IP", style="cyan")
            events_table.add_column("风险等级", style="red")
            events_table.add_column("事件类型", style="yellow")
            events_table.add_column("描述", style="white")
            
            for event in high_risk_events[:5]:  # 显示前5个
                events_table.add_row(
                    event.get("ip", "未知"),
                    event.get("risk_level", "未知"),
                    event.get("event_type", "未知"),
                    event.get("description", "未知")
                )
                
            console.print(events_table)
            
            if len(high_risk_events) > 5:
                console.print(f"... 还有 {len(high_risk_events) - 5} 个高风险事件未显示")
        
        # 打印预测攻击
        if predicted_attacks:
            console.print("\n[bold]预测攻击:[/]")
            predictions_table = Table()
            predictions_table.add_column("目标IP", style="cyan")
            predictions_table.add_column("攻击类型", style="yellow")
            predictions_table.add_column("概率", style="red")
            predictions_table.add_column("时间框架", style="white")
            
            for attack in predicted_attacks:
                predictions_table.add_row(
                    attack.get("target_ip", "未知"),
                    attack.get("attack_type", "未知"),
                    f"{attack.get('probability', 0)}%",
                    attack.get("timeframe", "未知")
                )
                
            console.print(predictions_table)
    except Exception as e:
        logger.error(f"打印摘要时出错: {str(e)}")
        print("\n安全巡检已完成，详细结果请查看日志和报告文件。")

def send_alert_email(result, time_range):
    """发送安全提醒邮件"""
    if not EMAIL_CONFIG["enabled"]:
        return
        
    try:
        risk_level = result.get("ai_insight", {}).get("risk_level", "未知")
        smart_score = result.get("ai_insight", {}).get("smart_score", 0)
        high_risk_events = result.get("ai_insight", {}).get("high_risk_events", [])
        
        # 构建邮件内容
        subject = f"[安全警报] 检测到高风险安全事件 - {datetime.now().strftime('%Y-%m-%d %H:%M')}"
        
        # 构建HTML内容
        html = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; }}
                .header {{ background-color: #f44336; color: white; padding: 10px; }}
                .content {{ padding: 15px; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                .risk-high {{ color: #f44336; font-weight: bold; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h2>网络安全警报</h2>
            </div>
            <div class="content">
                <p>系统在{time_range}内检测到高风险安全事件，请立即查看和处理。</p>
                
                <h3>安全摘要</h3>
                <ul>
                    <li>风险等级: <span class="risk-high">{risk_level}</span></li>
                    <li>安全评分: {smart_score}</li>
                    <li>高风险事件数量: {len(high_risk_events)}</li>
                </ul>
                
                <h3>高风险事件</h3>
                <table>
                    <tr>
                        <th>IP地址</th>
                        <th>风险等级</th>
                        <th>事件类型</th>
                        <th>描述</th>
                    </tr>
        """
        
        # 添加高风险事件
        for event in high_risk_events[:10]:  # 最多显示10个
            html += f"""
                    <tr>
                        <td>{event.get('ip', '未知')}</td>
                        <td>{event.get('risk_level', '未知')}</td>
                        <td>{event.get('event_type', '未知')}</td>
                        <td>{event.get('description', '未知')}</td>
                    </tr>
            """
            
        # 完成HTML
        html += """
                </table>
                
                <p>请登录安全管理系统查看完整报告和处理建议。</p>
            </div>
        </body>
        </html>
        """
        
        # 构建邮件
        msg = MIMEMultipart()
        msg["Subject"] = subject
        msg["From"] = EMAIL_CONFIG["from_email"]
        msg["To"] = ", ".join(EMAIL_CONFIG["to_emails"])
        
        # 添加HTML内容
        msg.attach(MIMEText(html, "html"))
        
        # 发送邮件
        with smtplib.SMTP(EMAIL_CONFIG["smtp_server"], EMAIL_CONFIG["smtp_port"]) as server:
            server.starttls()
            server.login(EMAIL_CONFIG["username"], EMAIL_CONFIG["password"])
            server.send_message(msg)
            
        logger.info("已发送安全警报邮件")
    except Exception as e:
        logger.error(f"发送邮件时出错: {str(e)}")

def schedule_inspection(interval_hours):
    """调度定期巡检任务"""
    schedule.every(interval_hours).hours.do(run_security_inspection)
    logger.info(f"已设置每{interval_hours}小时执行一次安全巡检")
    
    while True:
        schedule.run_pending()
        time.sleep(60)  # 每分钟检查一次

def main():
    """主函数"""
    args = parse_arguments()
    
    # 更新Email配置
    if args.email:
        EMAIL_CONFIG["enabled"] = True
        if args.recipients:
            EMAIL_CONFIG["to_emails"] = args.recipients.split(",")
            
    # 显示配置信息
    logger.info("自动化网络安全巡检工具启动")
    logger.info(f"API URL: {API_URL}")
    logger.info(f"巡检间隔: {args.interval}小时")
    logger.info(f"Email通知: {'启用' if EMAIL_CONFIG['enabled'] else '禁用'}")
    
    # 立即运行一次
    if args.run_now:
        run_security_inspection()
        if not args.interval:
            return
    
    # 启动定时任务
    schedule_inspection(args.interval)

if __name__ == "__main__":
    main() 