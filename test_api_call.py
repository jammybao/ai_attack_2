'''
Description: 
version: 
Author: Bao Jiaming
Date: 2025-04-03 03:34:35
LastEditTime: 2025-04-03 03:57:19
FilePath: \test_api_call.py
'''
#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
简单的API测试脚本
"""
import requests
import json
import re
import ast

# 发送请求
response = requests.post(
    "http://localhost:8000/api/v1/query",
    json={
        "question": "分析最近一周的网络攻击，重点关注高风险攻击和外部IP，评估风险等级",
        "use_ml": True
    },
    timeout=30
)

# 检查响应状态
print(f"状态码: {response.status_code}")
if response.status_code == 200:
    print("请求成功")
    result = response.json()
    
    # 打印完整响应结果
    print("\n完整响应结果:")
    print(json.dumps(result, indent=2, ensure_ascii=False))
    
    # 打印SQL查询
    print("\n执行的SQL查询:")
    print(result.get("sql_query", "未找到SQL查询"))
    
    # 打印SQL结果
    print("\nSQL查询结果:")
    sql_result = result.get("sql_result", "未找到SQL结果")
    print(sql_result)
    
    # 尝试查找高风险记录
    print("\n分析SQL结果中的高风险记录:")
    try:
        # 首先尝试解析为JSON
        high_risk_records = []
        try:
            # 尝试解析JSON格式
            json_data = json.loads(sql_result)
            if isinstance(json_data, list):
                for row in json_data:
                    if isinstance(row, dict) and "threat_level" in row:
                        threat_level = row["threat_level"]
                        # 转换threat_level为数字
                        try:
                            if isinstance(threat_level, str):
                                if threat_level.lower() == "高":
                                    threat_level = 40
                                elif threat_level.lower() == "中":
                                    threat_level = 20
                                elif threat_level.lower() == "低":
                                    threat_level = 10
                                else:
                                    threat_level = float(threat_level)
                        except:
                            continue
                            
                        # 检查是否高风险(threat_level >= 30)
                        if threat_level >= 30:
                            high_risk_records.append(row)
                            print(f"找到高风险记录: {row}")
        except:
            # 如果不是JSON，尝试字符串解析
            if "threat_level" in sql_result or "datetime.datetime" in sql_result:
                print("检测到元组格式的SQL结果，尝试解析...")
                
                # 修复SQL结果字符串格式
                # 由于SQL结果是一个Python元组的字符串表示
                # 这里尝试将其解析为实际的Python对象
                try:
                    # 将字符串直接转换为Python对象
                    sql_result_fixed = sql_result.replace("datetime.datetime", "None")  # 简化处理datetime对象
                    tuple_data = ast.literal_eval(sql_result_fixed)
                    print(f"成功解析元组数据: {tuple_data}")
                    
                    # 这是一个元组，第二个元素是threat_level
                    if isinstance(tuple_data, tuple) and len(tuple_data) >= 2:
                        threat_level = tuple_data[1]  # 第二个元素是threat_level
                        if threat_level >= 30:
                            print(f"找到高风险记录: threat_level={threat_level}, src_ip={tuple_data[3]}, signature={tuple_data[6]}")
                            
                            # 创建结构化的事件数据
                            event = {
                                "ip": tuple_data[3],  # src_ip
                                "risk_level": "高",
                                "event_type": tuple_data[2],  # category
                                "description": tuple_data[6]  # signature
                            }
                            print(f"应该添加到high_risk_events的事件: {event}")
                except Exception as e:
                    print(f"解析元组数据失败: {str(e)}")
                    
                # 传统方式尝试提取元组/列表格式的记录
                pattern = r'\(([^)]+)\)'
                matches = re.findall(pattern, sql_result)
                
                for match in matches:
                    print(f"匹配到的元组内容: {match}")
                    # 分割字段
                    fields = match.split(", ")
                    print(f"分割后的字段: {fields}")
                    if len(fields) >= 2:  # 至少要有event_time和threat_level
                        # 尝试提取threat_level
                        threat_level_str = fields[1].strip("'\"")
                        try:
                            threat_level = float(threat_level_str)
                            if threat_level >= 30:
                                print(f"找到高风险记录: {match}")
                                print(f"threat_level={threat_level}, src_ip={fields[3] if len(fields) > 3 else 'Unknown'}")
                                high_risk_records.append(match)
                        except Exception as e:
                            print(f"解析threat_level失败: {str(e)}")
                            continue
        
        if not high_risk_records:
            print("未在SQL结果中找到任何高风险记录")
    except Exception as e:
        print(f"分析SQL结果时出错: {str(e)}")
    
    # 打印extract_ai_insight函数应该看到的数据
    print("\n提供给extract_ai_insight函数的数据:")
    print(f"SQL查询: {result.get('sql_query', '')}")
    print(f"SQL结果: {result.get('sql_result', '')}")
    print(f"分析结果: {json.dumps(result.get('security_analysis', {}), indent=2, ensure_ascii=False)}")
    
    # 检查AI洞察字段
    if "ai_insight" in result:
        print("\nAI洞察数据:")
        ai_insight = result["ai_insight"]
        
        print(f"智能打分: {ai_insight.get('smart_score', 'N/A')}")
        print(f"外部IP攻击次数: {ai_insight.get('external_attack_count', 'N/A')}")
        print(f"风险等级: {ai_insight.get('risk_level', 'N/A')}")
        
        # 打印高风险事件
        high_risk_events = ai_insight.get("high_risk_events", [])
        if high_risk_events:
            print("\n高风险攻击事件:")
            for event in high_risk_events:
                print(f"  - IP: {event.get('ip', '未知')}, 类型: {event.get('event_type', '未知')}, 描述: {event.get('description', '未知')}")
        else:
            print("\n没有高风险攻击事件！")
        
        # 打印预测攻击
        predicted_attacks = ai_insight.get("predicted_attacks", [])
        if predicted_attacks:
            print("\n预测攻击:")
            for attack in predicted_attacks:
                print(f"  - 目标IP: {attack.get('target_ip', '未知')}, 类型: {attack.get('attack_type', '未知')}, 概率: {attack.get('probability', 0)}%")
    else:
        print("响应中没有AI洞察字段")
else:
    print(f"请求失败: {response.text}") 