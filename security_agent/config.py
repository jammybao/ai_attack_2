'''
Description: 
version: 
Author: Bao Jiaming
Date: 2025-03-07 23:10:53
LastEditTime: 2025-03-08 00:59:36
FilePath: \security_agent\config.py
'''
"""
配置文件
"""
import os
from pydantic_settings import BaseSettings, SettingsConfigDict
from dotenv import load_dotenv

# 加载环境变量
load_dotenv()

class Settings(BaseSettings):
    """应用程序设置"""
    # API配置
    API_V1_STR: str = "/api/v1"
    
    # 主机和端口配置
    HOST: str = "0.0.0.0"  # 默认值，可被环境变量覆盖
    PORT: int = 8000       # 默认值，可被环境变量覆盖
    
    # 通义千问API配置
    TONGYI_API_KEY: str = ""  # 敏感信息，不设默认值，必须从环境变量获取
    TONGYI_MODEL_NAME: str = "qwen-plus"  # 默认值
    TONGYI_BASE_URL: str = "https://dashscope.aliyuncs.com/compatible-mode/v1"  # 默认值
    
    # 数据库配置
    # 旧的SQLite配置
    # DB_CONNECTION_STRING: str = "sqlite:///./security_logs.db"  # 默认值
    
    # 新的MySQL配置
    DB_USER: str = os.getenv("DB_USER", "itm_wxp")
    DB_PASSWORD: str = os.getenv("DB_PASSWORD", "itmWxp@.0402")
    DB_HOST: str = os.getenv("DB_HOST", "localhost")
    DB_PORT: str = os.getenv("DB_PORT", "3306")
    DB_NAME: str = os.getenv("DB_NAME", "itm")
    
    # 构建连接字符串
    DB_CONNECTION_STRING: str = f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
    SECURITY_LOGS_TABLE: str = os.getenv("SECURITY_LOGS_TABLE", "ids_ai")
    
    # 日志配置
    LOG_LEVEL: str = "INFO"  # 默认值
    
    # 使用新的配置方式
    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=True,
        extra="ignore"  # 允许额外的字段
    )

# 创建设置实例
settings = Settings()