# 网络安全智能巡检系统

基于 AI 和机器学习的智能网络安全巡检系统，可自动定期检测网络安全威胁，生成安全报告，并提供预测性安全分析。

## 主要功能

1. **智能安全分析**：使用 AI 和机器学习分析安全事件并评估风险
2. **自动化安全巡检**：定时自动执行安全检查，保存历史报告
3. **外部 IP 监控**：特别关注来自外部 IP 的潜在攻击活动
4. **攻击预测**：基于历史数据预测可能的未来攻击
5. **安全警报**：高风险威胁自动发送邮件通知

## 系统架构

- **API 服务**：基于 FastAPI 的 REST API 服务，提供安全查询接口
- **AI 分析引擎**：集成多种机器学习模型，包括异常检测、IP 信誉分析和攻击链预测
- **自动巡检模块**：定时执行安全巡检任务，生成安全报告
- **可视化报告**：使用 Rich 库提供美观的命令行输出

## 安装和配置

### 前提条件

- Python 3.8+
- 数据库（MySQL/MariaDB）

### 安装依赖

```bash
pip install -r requirements.txt
```

### 配置

1. 复制`.env.example`为`.env`并配置数据库连接：

```ini
DB_HOST=localhost
DB_PORT=3306
DB_USER=your_user
DB_PASSWORD=your_password
DB_NAME=security_db
```

2. 配置电子邮件通知（可选）：

在`auto_inspection.py`中修改`EMAIL_CONFIG`配置。

## 使用方法

### 启动 API 服务

```bash
python run.py
```

服务默认运行在 http://localhost:8000

### 手动测试 API

```bash
python test_api_call_simple.py
```

### 运行自动巡检

```bash
# 每小时自动巡检
python auto_inspection.py

# 立即运行一次巡检
python auto_inspection.py --run-now

# 设置不同的巡检间隔（小时）
python auto_inspection.py --interval 2

# 启用电子邮件通知
python auto_inspection.py --email --recipients admin@example.com,security@example.com
```

## API 接口

### 查询接口

**POST** `/api/v1/query`

请求体:

```json
{
  "question": "分析最近一周的网络攻击，重点关注高风险攻击和外部IP，评估风险等级",
  "use_ml": true
}
```

响应格式:

```json
{
  "question": "...",
  "sql_query": "...",
  "sql_result": "...",
  "security_analysis": { ... },
  "formatted_answer": "...",
  "ai_insight": {
    "smart_score": 85,
    "external_attack_count": 2,
    "high_risk_events": [ ... ],
    "predicted_attacks": [ ... ],
    "risk_level": "中"
  }
}
```

## 常见问题

**问题：API 服务启动失败**

- 检查数据库连接配置
- 确认端口 8000 未被占用

**问题：自动巡检脚本报错**

- 确保 API 服务正在运行
- 检查权限，确保可以创建和写入报告目录

**问题：邮件通知不工作**

- 检查 SMTP 服务器配置
- 确认网络连接和防火墙设置

## 许可证

MIT License
