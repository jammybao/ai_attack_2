# AI安全分析API接口结构设计文档

## API响应结构概述

我们在原有API基础上进行了升级，添加了结构化的`ai_insight`字段，该字段提供了更加易于集成和可视化的安全分析数据。此升级设计旨在更好地展示AI/ML项目的价值，并便于与飞书等生态系统进行集成。

### 完整响应结构

```json
{
    "question": "用户原始问题",
    "sql_query": "生成的SQL查询",
    "sql_result": "SQL查询结果",
    "security_analysis": "详细的安全分析结果",
    "formatted_answer": "人类可读的格式化回答",
    "ai_insight": {
        "smart_score": 95,                // 智能打分系统得分(0-100)
        "external_attack_count": 5,       // 外部IP攻击次数
        "high_risk_events": [             // 高风险攻击事件
            {
                "ip": "45.132.192.12",
                "risk_level": "高",
                "event_type": "漏洞利用",
                "description": "远程命令执行尝试"
            },
            // 更多高风险事件...
        ],
        "predicted_attacks": [            // 预测可能会收到的攻击
            {
                "target_ip": "192.168.10.5",
                "attack_type": "命令执行",
                "probability": 78.5,      // 攻击概率(百分比)
                "timeframe": "24小时内"
            },
            // 更多预测攻击...
        ],
        "risk_level": "高"                // 整体风险等级
    }
}
```

## ai_insight字段详解

### 1. smart_score - 智能打分系统

智能打分系统根据安全分析的全面性和风险等级计算得分，范围从0到100：
- 90-100: 极高风险，需要立即处理
- 70-89: 高风险，需要优先处理
- 50-69: 中等风险，需要计划处理
- 30-49: 低风险，可以监控
- 0-29: 极低风险，正常情况

此评分可以直接用于数据可视化中的仪表盘组件，展示系统当前的整体安全状况。

### 2. external_attack_count - 外部IP攻击次数

此数字表示检测到的外部IP对内网发起的攻击总次数。外部IP被定义为不在内部网络中的IP地址。

此数据适合用于：
- 趋势图表，展示一段时间内的攻击次数变化
- 热力图，展示不同时间段的攻击频率
- 数值卡片，展示当前攻击总数

### 3. high_risk_events - 高风险攻击事件

高风险攻击事件是系统检测到的最危险攻击的详细信息，每个事件包含：
- `ip`: 攻击源IP地址
- `risk_level`: 风险等级，通常为"高"
- `event_type`: 攻击类型，如"漏洞利用"、"暴力破解"
- `description`: 事件的详细描述

此数据适合用于：
- 表格展示，列出所有高风险事件
- 地理地图，显示攻击源的地理位置
- 饼图，展示不同类型攻击的比例

### 4. predicted_attacks - 预测攻击

基于AI机器学习模型预测的可能即将发生的攻击，包含：
- `target_ip`: 预测的攻击目标IP
- `attack_type`: 预测的攻击类型
- `probability`: 攻击发生的概率(0-100)
- `timeframe`: 预测的时间范围

此数据适合用于：
- 预警面板，展示需要特别关注的资产
- 概率条形图，展示不同攻击可能性的高低
- 时间轴，展示预计的攻击时间

### 5. risk_level - 整体风险等级

系统评估的整体安全风险等级，值为"高"、"中"、"低"或"未知"。

此评级可用于：
- 风险指示器，通过颜色直观展示当前风险(红色表示高风险，黄色表示中风险，绿色表示低风险)
- 状态标签，在仪表盘上方展示当前系统状态

## 与飞书生态集成建议

1. **飞书机器人集成**：
   - 开发一个飞书机器人，定期或在检测到高风险事件时自动推送安全简报
   - 推送内容可包含`smart_score`、`external_attack_count`和`high_risk_events`的摘要
   - 对于紧急情况，添加@相关负责人的提醒功能

2. **飞书多维表格集成**：
   - 创建安全事件记录表，自动将`high_risk_events`记录到表格中
   - 创建攻击预测表，将`predicted_attacks`记录到表格中
   - 利用多维表格的视图功能，创建不同维度的分析视图(按IP、按风险等级、按时间等)

3. **飞书仪表盘集成**：
   - 通过飞书应用实现自定义安全仪表盘
   - 展示`smart_score`的仪表盘组件
   - 展示`external_attack_count`的趋势图
   - 展示`high_risk_events`的表格视图
   - 展示`predicted_attacks`的预警面板

## 使用示例

### 1. 调用API获取安全分析

```python
import requests
import json

# 发送查询请求
response = requests.post(
    "http://your-api-endpoint/query",
    json={
        "question": "分析最近一周的网络攻击，重点关注高风险攻击和外部IP，评估风险等级",
        "use_ml": True
    }
)

# 解析响应
result = response.json()

# 从ai_insight中提取信息
smart_score = result["ai_insight"]["smart_score"]
attack_count = result["ai_insight"]["external_attack_count"]
high_risk_events = result["ai_insight"]["high_risk_events"]
predicted_attacks = result["ai_insight"]["predicted_attacks"]
risk_level = result["ai_insight"]["risk_level"]

# 输出关键信息
print(f"安全评分: {smart_score}/100 - 风险等级: {risk_level}")
print(f"检测到{attack_count}次外部IP攻击")
print("高风险事件:")
for event in high_risk_events:
    print(f"  - {event['ip']}: {event['description']} [{event['event_type']}]")
```

### 2. 集成到飞书机器人

```python
def send_to_feishu(ai_insight, webhook_url):
    """发送安全分析结果到飞书机器人"""
    
    # 构建卡片消息
    card = {
        "config": {
            "wide_screen_mode": True
        },
        "header": {
            "title": {
                "tag": "plain_text",
                "content": f"安全预警 - 风险等级: {ai_insight['risk_level']}"
            },
            "template": "red" if ai_insight['risk_level'] == "高" else 
                       ("orange" if ai_insight['risk_level'] == "中" else "green")
        },
        "elements": [
            {
                "tag": "div",
                "text": {
                    "tag": "lark_md",
                    "content": f"**安全评分**: {ai_insight['smart_score']}/100"
                }
            },
            {
                "tag": "div",
                "text": {
                    "tag": "lark_md",
                    "content": f"**外部攻击次数**: {ai_insight['external_attack_count']}"
                }
            },
            {
                "tag": "hr"
            },
            {
                "tag": "div",
                "text": {
                    "tag": "lark_md",
                    "content": "**高风险事件**:"
                }
            }
        ]
    }
    
    # 添加高风险事件
    for event in ai_insight['high_risk_events']:
        card["elements"].append({
            "tag": "div",
            "text": {
                "tag": "lark_md",
                "content": f"- {event['ip']}: {event['description']} [{event['event_type']}]"
            }
        })
    
    # 添加预测攻击
    if ai_insight['predicted_attacks']:
        card["elements"].append({
            "tag": "hr"
        })
        card["elements"].append({
            "tag": "div",
            "text": {
                "tag": "lark_md",
                "content": "**预测攻击**:"
            }
        })
        
        for attack in ai_insight['predicted_attacks']:
            card["elements"].append({
                "tag": "div",
                "text": {
                    "tag": "lark_md",
                    "content": f"- 目标 {attack['target_ip']}: {attack['attack_type']} (概率: {attack['probability']}%)"
                }
            })
    
    # 发送到飞书
    message = {
        "msg_type": "interactive",
        "card": card
    }
    
    response = requests.post(webhook_url, json=message)
    return response.status_code == 200
```

## 结论

通过增强的API响应结构，我们为AI安全分析系统提供了更加结构化、可视化和易于集成的数据格式。`ai_insight`字段的设计使得机器学习项目的价值能够更加清晰地展示给领导和其他利益相关者，同时便于与飞书等生态系统进行集成。

这种设计不仅符合现代API设计的最佳实践，还特别关注了数据的可视化和可操作性，使得安全分析结果能够直接转化为可行的安全措施。 