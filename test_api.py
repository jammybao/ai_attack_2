'''
Description: 
version: 
Author: Bao Jiaming
Date: 2025-03-24 02:21:24
LastEditTime: 2025-03-24 03:02:19
FilePath: \test_api.py
'''
"""
测试官方SQL链API接口
"""
import requests
import json
import time

# API请求URL
url = "http://localhost:8000/api/v1/sql/query"

# 请求头
headers = {
    "Content-Type": "application/json"
}

# 请求体
payload = {
    "question": "上一周高危报警的分析报告",
    "table_names": ["ids_ai"]
}

def test_api():
    print("开始测试API...")
    print(f"请求URL: {url}")
    print(f"请求体: {json.dumps(payload, ensure_ascii=False, indent=2)}")
    
    try:
        # 发送POST请求
        response = requests.post(url, json=payload, headers=headers)
        
        # 检查响应状态码
        print(f"响应状态码: {response.status_code}")
        
        # 如果成功，打印响应内容
        if response.status_code == 200:
            result = response.json()
            
            print("\n响应内容 (JSON格式):")
            print(json.dumps(result, ensure_ascii=False, indent=2))
            
            print("\n实际答案内容 (原始格式):")
            print("=" * 80)
            print(result["answer"])
            print("=" * 80)
        else:
            print(f"请求失败: {response.text}")
    
    except Exception as e:
        print(f"发生错误: {e}")

if __name__ == "__main__":
    # 等待服务器启动
    print("等待服务器启动...")
    time.sleep(5)
    
    # 测试API
    test_api() 