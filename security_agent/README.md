# 安全日志分析系统

基于LangChain 0.3和大语言模型的安全日志分析系统，可以自动查询数据库、生成SQL、执行查询并分析安全日志。

## 功能特点

- 自然语言查询：使用自然语言描述您的安全查询需求
- 自动SQL生成：系统自动生成SQL查询语句
- 安全日志分析：分析查询结果并生成专业的安全报告
- 定时报告：支持定时生成安全报告
- API接口：提供RESTful API接口，方便集成

## 安装

1. 克隆仓库
2. 安装依赖：

```bash
pip install -r requirements.txt
```

3. 配置环境变量：

创建`.env`文件，包含以下内容：

```
TONGYI_API_KEY=your_api_key
TONGYI_MODEL_NAME=qwen-max
TONGYI_BASE_URL=https://dashscope.aliyuncs.com/api/v1/services/aigc/text-generation/generation
DB_CONNECTION_STRING=mysql+pymysql://username:password@host/database
SECURITY_LOGS_TABLE=ids_ai
```

## 使用方法

### 启动API服务

```bash
uvicorn security_agent.main:app --reload
```

### API接口

#### 1. 安全日志分析

```
POST /security/analyze
```

请求体：

```json
{
  "query": "前8小时是否有网络安全攻击风险"
}
```

#### 2. 生成安全报告

```
POST /security/report
```

请求体：

```json
{
  "report_type": "general",
  "hours": 8
}
```

可用的报告类型：
- `general`: 一般安全概况报告
- `high_risk`: 高风险安全事件报告
- `login_failure`: 登录失败记录报告
- `attack`: 网络攻击事件报告

#### 3. 查询安全数据库

```
POST /security/query
```

请求体：

```json
{
  "question": "最近24小时内有哪些高危安全事件？",
  "time_range": {
    "start_time": "2025-03-06 00:00:00",
    "end_time": "2025-03-07 00:00:00"
  }
}
```

#### 4. 定时安全报告

```
GET /security/scheduled_report/{report_type}?hours=8
```

### 定时任务

可以使用cron或其他定时任务工具定期执行`security_agent/scripts/scheduled_report.py`脚本，生成安全报告。

示例cron配置（每小时生成一次报告）：

```
0 * * * * cd /path/to/project && python -m security_agent.scripts.scheduled_report --report-type general --hours 1
```

脚本使用方法：

```bash
python -m security_agent.scripts.scheduled_report --help
```

```
usage: scheduled_report.py [-h] [--api-url API_URL] [--report-type {general,high_risk,login_failure,attack}] [--hours HOURS] [--output-dir OUTPUT_DIR]

定时安全报告生成工具

options:
  -h, --help            show this help message and exit
  --api-url API_URL     API服务器URL
  --report-type {general,high_risk,login_failure,attack}
                        报告类型
  --hours HOURS         报告时间范围（小时）
  --output-dir OUTPUT_DIR
                        报告输出目录
```

## 开发

### 项目结构

```
security_agent/
├── api/                # API接口
│   ├── __init__.py
│   └── routes.py       # API路由定义
├── chains/             # LangChain链
│   ├── __init__.py
│   ├── security_agent_chain.py  # 安全代理链
│   ├── sql_generator_chain.py   # SQL生成链
│   └── time_parser_chain.py     # 时间解析链
├── scripts/            # 脚本
│   └── scheduled_report.py      # 定时报告脚本
├── tests/              # 测试
│   ├── integration/    # 集成测试
│   └── unit/           # 单元测试
├── config.py           # 配置
├── main.py             # 主程序
└── README.md           # 说明文档
```

### 测试

运行单元测试：

```bash
pytest security_agent/tests/unit/
```

运行集成测试：

```bash
pytest security_agent/tests/integration/
``` 