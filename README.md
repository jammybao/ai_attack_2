# 网络安全 AI 代理

基于通义千问 API 的网络安全日志分析和入侵检测系统。

## 项目概述

本项目旨在开发一个基于通义千问大语言模型 API 的 AI 代理，用于网络安全日志分析和入侵检测。该代理使用 LangChain 框架实现链式调用，允许用户通过自然语言指定时间范围（如"前 8 小时"、"昨天下午"等），系统自动解析时间范围，从安全日志数据库获取相应数据并进行智能分析，通过 API 向外部系统提供分析结果。

## 系统架构

系统由以下主要组件构成：

1. **API 接口层**：接收用户查询，返回分析结果
2. **时间解析链**：使用 LLM 解析自然语言时间描述
3. **SQL 生成链**：根据解析的时间范围生成数据库查询
4. **数据访问层**：执行 SQL 查询，获取原始日志数据
5. **数据处理链**：清洗、格式化和汇总日志数据
6. **安全分析链**：使用 LLM 分析日志数据，识别安全威胁
7. **结果处理层**：解析和格式化 AI 分析结果
8. **AI 洞察层**：提供结构化的安全评估数据，便于可视化和系统集成

## 安装与配置

### 环境要求

- Python 3.9+
- 通义千问 API 密钥

### 安装步骤

1. 克隆仓库：

```bash
git clone <repository-url>
cd security-agent
```

2. 安装依赖：

```bash
pip install -r requirements.txt
```

3. 配置环境变量：

```bash
cp .env.example .env
```

编辑 `.env` 文件，填入您的通义千问 API 密钥和其他配置。

### 初始化数据库

```bash
python -c "from security_agent.utils.db_init import init_database; init_database()"
```

## 使用方法

### 启动服务

```bash
python -m security_agent.main
```

服务将在 `http://localhost:8000` 启动。

### API 使用示例

分析特定时间范围的安全风险：

```bash
curl -X POST "http://localhost:8000/api/query" \
     -H "Content-Type: application/json" \
     -d '{"question": "分析最近一周的网络攻击，重点关注高风险攻击和外部IP，评估风险等级", "use_ml": true}'
```

### 测试新版API结构

```bash
python test_new_api.py --url http://localhost:8000/api --question "分析最近一周的网络攻击，重点关注高风险攻击和外部IP，评估风险等级"
```

## API响应结构

API 响应包含以下关键字段：

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
            }
        ],
        "predicted_attacks": [            // 预测可能会收到的攻击
            {
                "target_ip": "192.168.10.5",
                "attack_type": "命令执行",
                "probability": 78.5,      // 攻击概率(百分比)
                "timeframe": "24小时内"
            }
        ],
        "risk_level": "高"                // 整体风险等级
    }
}
```

### ai_insight 字段详解

`ai_insight` 字段提供了结构化的安全评估数据，便于系统集成和数据可视化：

1. **smart_score**：AI 智能打分系统评分(0-100)，反映整体安全状况
2. **external_attack_count**：检测到的外部IP攻击总次数
3. **high_risk_events**：高风险攻击事件的详细信息，包括攻击源IP、风险等级、攻击类型和描述
4. **predicted_attacks**：AI模型预测的可能即将发生的攻击，包括目标IP、攻击类型、概率和时间范围
5. **risk_level**：整体风险等级评估，值为"高"、"中"、"低"或"未知"

这些结构化字段使得安全分析结果可以更容易地：
- 集成到监控系统和仪表盘
- 通过飞书等协作平台分享和展示
- 用于自动化安全响应和决策支持

更多详细说明请参考 [`api_structure_guide.md`](api_structure_guide.md)。

## 项目结构

```
security_agent/
├── api/                # API接口层
├── chains/             # 链式处理组件
├── database/           # 数据库访问层
├── models/             # 数据模型
├── tests/              # 测试文件
│   ├── unit/           # 单元测试
│   └── integration/    # 集成测试
└── utils/              # 工具函数
```

## 运行测试

```bash
pytest
```

## 许可证

[MIT](LICENSE)

## 贡献指南

欢迎贡献代码、报告问题或提出改进建议。请遵循以下步骤：

1. Fork 仓库
2. 创建特性分支 (`git checkout -b feature/amazing-feature`)
3. 提交更改 (`git commit -m 'Add some amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 创建 Pull Request
