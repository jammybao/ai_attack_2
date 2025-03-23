# 安全代理 API

本 API 提供了一个简单的接口，用于通过 OfficialSQLChain 查询数据库并获取安全分析结果。

## API 端点

### 查询数据库

**URL**: `/api/v1/sql/query`
**方法**: POST
**描述**: 使用自然语言问题查询数据库并返回安全分析结果。

**请求体**:

```json
{
  "question": "上一周高危报警的分析报告",
  "table_names": ["ids_ai"] // 可选，要查询的表名列表
}
```

**响应**:

```json
{
  "question": "上一周高危报警的分析报告",
  "answer": "## 安全分析结果\n\n**风险等级**: 高\n\n### 关键发现\n\n- 过去一周共发现32起高危报警事件\n- 主要攻击来源IP为192.168.1.100，占总攻击的30%\n- 最常见的攻击类型为SQL注入尝试\n\n### 安全建议\n\n- 立即更新所有Web应用程序防火墙规则\n- 对受攻击的系统进行全面漏洞扫描\n- 增强对攻击源IP的监控和封锁措施\n\n### 详细分析\n\n过去一周的高危报警事件主要集中在Web应用层面，攻击者主要针对未及时修复的CVE-2023-1234漏洞。这些攻击尝试主要来自几个固定的IP地址，显示出有组织的攻击模式。建议立即部署相关补丁并加强网络边界防护。"
}
```

## 使用示例

### Python

```python
import requests
import json

url = "http://localhost:8000/api/v1/sql/query"
payload = {
    "question": "上一周高危报警的分析报告",
    "table_names": ["ids_ai"]
}
headers = {
    "Content-Type": "application/json"
}

response = requests.post(url, data=json.dumps(payload), headers=headers)
result = response.json()
print(result["answer"])
```

### Curl

```bash
curl -X POST "http://localhost:8000/api/v1/sql/query" \
     -H "Content-Type: application/json" \
     -d '{"question": "上一周高危报警的分析报告", "table_names": ["ids_ai"]}'
```

## 注意事项

- 确保在运行服务器之前已设置好所有必要的环境变量，包括数据库连接和 API 密钥。
- 对于较为复杂或特定的查询，可能需要在 question 中提供更详细的描述。
- 默认情况下，如果不提供表名，系统会尝试使用所有可用的表。
