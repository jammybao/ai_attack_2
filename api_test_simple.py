#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
简单的API测试脚本，保存原始JSON响应
"""
import requests
import json
from datetime import datetime

# 发送查询 - 使用简单的常规接口调用
print("开始发送API请求...")
try:
    response = requests.post(
        "http://localhost:8000/api/v1/query",
        json={
            "question": "分析最近一周的网络攻击，重点关注高风险攻击和外部IP，评估风险等级",
            "use_ml": True
        },
        timeout=60  # 增加超时时间到60秒
    )
    
    # 检查响应
    print(f"状态码: {response.status_code}")
    if response.status_code == 200:
        # 获取原始JSON结果
        result = response.json()
        
        # 添加元数据
        result["_meta"] = {
            "timestamp": datetime.now().isoformat(),
            "status_code": response.status_code
        }
        
        # 保存为JSON文件
        filename = f"api_response_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        
        print(f"API响应已保存到: {filename}")
        
        # 打印部分信息
        print("\n基本响应信息:")
        print(f"- 外部IP攻击次数: {result.get('ai_insight', {}).get('external_attack_count', '未知')}")
        print(f"- 风险等级: {result.get('ai_insight', {}).get('risk_level', '未知')}")
        print(f"- 高风险事件数: {len(result.get('ai_insight', {}).get('high_risk_events', []))}")
        
    else:
        print(f"请求失败: {response.text}")
        
except requests.exceptions.Timeout:
    print("请求超时! 服务器没有在规定时间内响应。")
except requests.exceptions.ConnectionError:
    print("连接错误! 无法连接到API服务器。请确保服务正在运行。")
except Exception as e:
    print(f"发生错误: {str(e)}") 