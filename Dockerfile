FROM python:3.10-slim

WORKDIR /app

# 复制项目文件
COPY requirements.txt .
COPY run.py .
COPY security_agent ./security_agent

# 安装依赖
RUN pip install --no-cache-dir -r requirements.txt

# 暴露端口
EXPOSE 8000

# 启动应用
CMD ["python", "run.py"] 