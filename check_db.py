'''
Description: 
version: 
Author: Bao Jiaming
Date: 2025-03-17 09:05:30
LastEditTime: 2025-03-17 09:08:29
FilePath: \check_db.py
'''
from sqlalchemy import create_engine, text
from security_agent.config import settings
import logging

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def check_db():
    try:
        # 打印数据库连接字符串
        logger.info(f"数据库连接字符串: {settings.DB_CONNECTION_STRING}")
        
        # 创建数据库引擎
        engine = create_engine(settings.DB_CONNECTION_STRING)
        logger.info("成功创建数据库引擎")
        
        # 连接数据库并执行查询
        with engine.connect() as conn:
            logger.info("成功连接到数据库")
            
            # 检查表是否存在
            logger.info("检查ids_ai表是否存在")
            result = conn.execute(text("SHOW TABLES"))
            tables = [row[0] for row in result.fetchall()]
            logger.info(f"数据库中的表: {tables}")
            
            if 'ids_ai' not in tables:
                logger.warning("ids_ai表不存在")
                return
            
            # 获取记录数
            logger.info("获取ids_ai表中的记录数")
            result = conn.execute(text("SELECT COUNT(*) FROM ids_ai"))
            count = result.fetchone()[0]
            logger.info(f"ids_ai表中的记录数: {count}")
            
            # 如果有记录，查看一条示例
            if count > 0:
                logger.info("获取一条示例记录")
                result = conn.execute(text("SELECT * FROM ids_ai LIMIT 1"))
                row = result.fetchone()
                logger.info(f"示例记录: {row}")
                
                # 查询最近24小时内威胁等级大于等于30的安全事件
                logger.info("查询最近24小时内威胁等级大于等于30的安全事件")
                result = conn.execute(text("""
                    SELECT COUNT(*) FROM ids_ai 
                    WHERE event_time >= CURDATE() - INTERVAL 1 DAY 
                    AND threat_level >= 30
                """))
                high_threat_count = result.fetchone()[0]
                logger.info(f"最近24小时内威胁等级大于等于30的安全事件数: {high_threat_count}")
            else:
                logger.warning("ids_ai表中没有记录")
    except Exception as e:
        logger.error(f"检查数据库时出错: {e}")
        import traceback
        logger.error(traceback.format_exc())

if __name__ == "__main__":
    logger.info("开始检查数据库")
    check_db()
    logger.info("数据库检查完成") 