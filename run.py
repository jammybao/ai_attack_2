"""
项目启动脚本
"""
import os
import sys
import logging
from security_agent.utils.logger import setup_logger
from security_agent.utils.db_init import init_database

# 设置日志
logger = setup_logger()

def main():
    """主函数"""
    try:
        # 初始化数据库
        logger.info("初始化数据库...")
        init_database()
        
        # 启动API服务
        logger.info("启动API服务...")
        os.system("python -m security_agent.main")
    except Exception as e:
        logger.error(f"启动失败: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 