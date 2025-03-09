'''
Description: 
version: 
Author: Bao Jiaming
Date: 2025-03-04 12:48:51
LastEditTime: 2025-03-04 12:49:04
FilePath: \security_agent\utils\logger.py
'''
"""
日志工具
"""
import logging
import sys
from pathlib import Path

from security_agent.config import settings

def setup_logger():
    """设置日志记录器"""
    # 创建日志目录
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    
    # 获取日志级别
    log_level = getattr(logging, settings.LOG_LEVEL.upper())
    
    # 配置根日志记录器
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(log_dir / "security_agent.log")
        ]
    )
    
    # 设置第三方库的日志级别
    logging.getLogger("uvicorn").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy").setLevel(logging.WARNING)
    
    # 返回应用程序日志记录器
    logger = logging.getLogger("security_agent")
    logger.info(f"日志系统已初始化，级别: {settings.LOG_LEVEL}")
    
    return logger 