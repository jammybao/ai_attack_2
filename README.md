# 网络安全AI代理

基于通义千问API的网络安全日志分析和入侵检测系统。

## 项目概述

本项目旨在开发一个基于通义千问大语言模型API的AI代理，用于网络安全日志分析和入侵检测。该代理使用LangChain框架实现链式调用，允许用户通过自然语言指定时间范围（如"前8小时"、"昨天下午"等），系统自动解析时间范围，从安全日志数据库获取相应数据并进行智能分析，通过API向外部系统提供分析结果。

## 系统架构

系统由以下主要组件构成：

1. **API接口层**：接收用户查询，返回分析结果
2. **时间解析链**：使用LLM解析自然语言时间描述
3. **SQL生成链**：根据解析的时间范围生成数据库查询
4. **数据访问层**：执行SQL查询，获取原始日志数据
5. **数据处理链**：清洗、格式化和汇总日志数据
6. **安全分析链**：使用LLM分析日志数据，识别安全威胁
7. **结果处理层**：解析和格式化AI分析结果

## 安装与配置

### 环境要求

- Python 3.9+
- 通义千问API密钥

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

编辑 `.env` 文件，填入您的通义千问API密钥和其他配置。

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

### API使用示例

分析特定时间范围的安全风险：

```bash
curl -X POST "http://localhost:8000/api/security/analyze" \
     -H "Content-Type: application/json" \
     -d '{"query": "前8小时是否有网络安全攻击风险"}'
```

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