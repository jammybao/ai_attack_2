#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
定时安全报告脚本

此脚本可以通过cron或其他定时任务工具定期执行，用于生成安全报告
"""
import os
import sys
import argparse
import requests
import datetime
import logging
from pathlib import Path

# 设置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(f"security_report_{datetime.datetime.now().strftime('%Y%m%d')}.log")
    ]
)
logger = logging.getLogger(__name__)

def parse_args():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(description="定时安全报告生成工具")
    parser.add_argument(
        "--api-url", 
        default="http://localhost:8000", 
        help="API服务器URL"
    )
    parser.add_argument(
        "--report-type", 
        default="general",
        choices=["general", "high_risk", "login_failure", "attack"],
        help="报告类型"
    )
    parser.add_argument(
        "--hours", 
        type=int, 
        default=8, 
        help="报告时间范围（小时）"
    )
    parser.add_argument(
        "--output-dir", 
        default="./reports", 
        help="报告输出目录"
    )
    return parser.parse_args()

def generate_report(api_url, report_type, hours, output_dir):
    """生成安全报告
    
    Args:
        api_url: API服务器URL
        report_type: 报告类型
        hours: 报告时间范围（小时）
        output_dir: 报告输出目录
    """
    try:
        # 确保输出目录存在
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        
        # 构建API URL
        url = f"{api_url}/security/scheduled_report/{report_type}?hours={hours}"
        
        logger.info(f"正在请求安全报告: {url}")
        
        # 发送请求
        response = requests.get(url)
        response.raise_for_status()
        
        # 解析响应
        report_data = response.json()
        
        # 生成报告文件名
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{report_type}_report_{timestamp}.txt"
        filepath = os.path.join(output_dir, filename)
        
        # 写入报告内容
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(f"安全报告: {report_type}\n")
            f.write(f"生成时间: {report_data['timestamp']}\n")
            f.write(f"时间范围: {report_data['time_range']}\n")
            f.write("\n" + "="*50 + "\n\n")
            f.write(report_data['report_content'])
        
        logger.info(f"安全报告已生成: {filepath}")
        
        # 打印报告摘要
        logger.info(f"报告摘要: {report_data['summary']}")
        
        return filepath
    except Exception as e:
        logger.error(f"生成报告失败: {e}")
        return None

def main():
    """主函数"""
    args = parse_args()
    
    logger.info(f"开始生成{args.report_type}安全报告，时间范围: {args.hours}小时")
    
    report_path = generate_report(
        api_url=args.api_url,
        report_type=args.report_type,
        hours=args.hours,
        output_dir=args.output_dir
    )
    
    if report_path:
        logger.info(f"报告生成成功: {report_path}")
        return 0
    else:
        logger.error("报告生成失败")
        return 1

if __name__ == "__main__":
    sys.exit(main()) 