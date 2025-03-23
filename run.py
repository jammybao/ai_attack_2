"""
项目启动脚本 - 简化版
"""
import os
import logging
import uvicorn

# 设置基本日志配置
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("security_agent")

def main():
    """主函数"""
    try:
        # 从环境变量获取主机和端口，如果不存在则使用默认值
        host = os.getenv("HOST", "0.0.0.0")
        port = int(os.getenv("PORT", 8000))
        
        logger.info(f"启动API服务，监听地址: {host}:{port}...")
        
        # 直接启动API服务
        uvicorn.run(
            "security_agent.main:app", 
            host=host, 
            port=port, 
            reload=True,
            log_level="info"
        )
    except Exception as e:
        logger.error(f"启动失败: {e}")
        import sys
        sys.exit(1)

if __name__ == "__main__":
    main() 