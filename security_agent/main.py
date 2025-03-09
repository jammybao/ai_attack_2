'''
Description: 
version: 
Author: Bao Jiaming
Date: 2025-03-04 12:42:38
LastEditTime: 2025-03-04 12:44:00
FilePath: \security_agent\main.py
'''
"""
网络安全AI代理主入口文件
"""
import os
import uvicorn
from fastapi import FastAPI
from dotenv import load_dotenv

# 加载环境变量
load_dotenv()

# 导入API路由
from security_agent.api.routes import router as api_router

# 创建FastAPI应用
app = FastAPI(
    title="网络安全AI代理",
    description="基于通义千问API的网络安全日志分析和入侵检测系统",
    version="1.0.0"
)

# 注册路由
app.include_router(api_router, prefix="/api")

# 健康检查端点
@app.get("/health")
async def health_check():
    return {"status": "healthy"}

if __name__ == "__main__":
    # 从环境变量获取主机和端口，如果不存在则使用默认值
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", 8000))
    
    # 启动服务器
    uvicorn.run("security_agent.main:app", host=host, port=port, reload=True) 