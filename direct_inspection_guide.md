# 直接安全巡检模块使用指南

本指南介绍了如何使用新的直接安全巡检模块，以及它相比原有方案的优势。

## 背景

原有的安全巡检系统依赖于复杂的 SQL 生成逻辑，而且每次巡检都需要根据问题动态生成不同的 SQL。对于定时巡检这样的场景，我们可以使用更加直接、高效的方式来实现，特别是当巡检问题基本固定为"分析一小时内的网络攻击，重点关注高风险攻击和外部 IP，评估风险等级"时。

新的直接安全巡检模块专注于直接分析已有的安全数据，不依赖 SQL 生成，提供了更快、更可靠的巡检体验。

## 优势

1. **更加稳定**：不依赖复杂的 SQL 生成，避免了因问题理解错误导致的查询失败
2. **性能更高**：直接从数据库获取固定结构的数据，无需每次都生成和解析 SQL
3. **专注于分析**：将重心放在数据分析和结果解读上，而非 SQL 生成
4. **更好的风险预测**：基于所有可用数据进行预测，而非仅基于 SQL 结果
5. **扩展性更强**：可以轻松添加新的分析指标和风险评估因素

## 安装依赖

确保已安装所需的 Python 包：

```bash
pip install pandas numpy scikit-learn schedule rich
```

## 使用方法

### 方法 1：使用命令行运行

```bash
# 立即运行一次巡检，分析最近1小时的数据
python run_direct_inspection.py --run-now

# 设置每30分钟巡检一次，分析最近2小时的数据
python run_direct_inspection.py --interval 0.5 --hours 2

# 启用邮件通知
python run_direct_inspection.py --email --recipients admin@example.com,security@example.com
```

命令行参数：

- `--run-now`: 立即运行一次巡检，不等待定时
- `--interval <小时>`: 设置巡检间隔时间(小时)，默认为 1 小时
- `--hours <小时>`: 设置每次分析最近多少小时的数据，默认为 1 小时
- `--email`: 启用电子邮件通知
- `--recipients`: 电子邮件收件人，多个收件人用逗号分隔

### 方法 2：在 Python 代码中使用

```python
from security_agent.scheduled_inspection import DirectSecurityInspection

# 创建巡检实例
inspector = DirectSecurityInspection()

# 执行巡检，分析最近1小时的数据
result = inspector.run_inspection(hours=1)

# 格式化并打印结果
formatted_result = inspector.format_inspection_result(result)
print(formatted_result)
```

### 方法 3：集成到现有系统

可以将`DirectSecurityInspection`类集成到现有的安全系统中：

```python
from security_agent.scheduled_inspection import DirectSecurityInspection

# 创建带自定义配置的巡检实例
inspector = DirectSecurityInspection(
    db_path="custom_security_logs.db",
    reports_dir="custom_reports",
    anomaly_model_path="models/anomaly_model.pkl",
    ip_reputation_model_path="models/ip_reputation.pkl",
    attack_chain_model_path="models/attack_chain.pkl"
)

# 执行巡检
result = inspector.run_inspection(hours=1)

# 处理结果，例如发送通知
if result["risk_level"] == "高":
    send_alert(result)
```

## 结果格式

巡检结果是一个包含以下字段的字典：

- **risk_level**: 整体风险等级（"高"、"中"、"低"或"未知"）
- **smart_score**: 智能安全评分（0-100，越高越安全）
- **external_attack_count**: 外部 IP 攻击次数
- **high_risk_events**: 高风险事件列表
- **key_findings**: 关键发现列表
- **recommendations**: 安全建议列表
- **predicted_attacks**: 预测攻击列表

示例结果：

```json
{
  "risk_level": "高",
  "smart_score": 65,
  "external_attack_count": 12,
  "high_risk_events": [
    {
      "ip": "192.168.1.100",
      "risk_level": "高",
      "event_type": "SQL注入",
      "description": "HTTP_注入攻击_算法_请求头SQL注入"
    }
    // 更多事件...
  ],
  "key_findings": ["发现8个高风险安全事件，需要注意", "发现3次SQL注入尝试"],
  "recommendations": ["检查并加固Web应用的输入验证机制，防止SQL注入"],
  "predicted_attacks": [
    {
      "target_ip": "192.168.1.200",
      "attack_type": "SQL注入",
      "probability": 85,
      "timeframe": "24小时内"
    }
  ]
}
```

## 自定义与扩展

### 添加新的事件类型分析

可以通过扩展`_classify_event_type`方法来支持更多事件类型：

```python
def _classify_event_type(self, signature: str) -> str:
    signature = signature.lower()

    # 添加新的事件类型检测逻辑
    if 'ransom' in signature or '勒索' in signature:
        return "勒索软件"
    # 原有的检测逻辑...
```

### 添加新的风险评分因素

可以扩展`_calculate_risk_level`和`_calculate_smart_score`方法来加入新的风险评分因素：

```python
def _calculate_risk_level(self, data: pd.DataFrame, high_risk_events: List[Dict], external_attack_count: int) -> str:
    # 原有代码...

    # 添加新的风险评分因素
    ransomware_events = [event for event in high_risk_events if event.get("event_type") == "勒索软件"]
    if ransomware_events:
        factors.append(3)  # 高风险

    # 原有代码...
```

## 注意事项

1. 确保数据库结构符合预期，包含`ids_ai`和`ip_address`表
2. 对于生产环境，建议配置适当的邮件通知设置
3. 模型文件路径可以根据需要进行配置
4. 如需自定义报告格式，可以修改`format_inspection_result`方法

## 与原有系统的兼容性

新的直接安全巡检模块与原有系统并行运行，不会影响原有功能。您可以同时使用两种方式，并根据需要逐步迁移到新的直接巡检方式。

## 故障排除

### 常见问题

1. **数据库连接失败**

   - 检查数据库文件路径是否正确
   - 确保有数据库读取权限

2. **模型加载失败**

   - 如果指定了模型路径但文件不存在，将使用默认模型
   - 检查模型文件格式是否正确

3. **没有检测到高风险事件**
   - 检查数据库中是否有符合条件的记录
   - 尝试增加分析时间范围（使用`--hours`参数）

## 总结

直接安全巡检模块通过专注于固定的巡检需求，提供了更高效、更可靠的安全分析能力。它避免了不必要的 SQL 生成复杂性，将重心放在数据分析和风险评估上，特别适合定时巡检场景。
