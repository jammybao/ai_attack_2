'''
Description: 
version: 
Author: Bao Jiaming
Date: 2025-03-04 12:46:11
LastEditTime: 2025-03-07 12:05:24
FilePath: \security_agent\chains\time_parser_chain.py
'''
"""
时间解析链
"""
from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import JsonOutputParser
from datetime import datetime, timedelta
import json
import logging

logger = logging.getLogger(__name__)

class TimeRangeParserChain:
    """时间范围解析链"""
    
    def __init__(self, api_key, model_name="qwen-plus", base_url="https://dashscope.aliyuncs.com/compatible-mode/v1"):
        """初始化时间解析链"""
        logger.info("初始化时间解析链")
        
        # 初始化LLM (使用通义千问API)
        self.llm = ChatOpenAI(
            model_name=model_name,
            api_key=api_key,
            base_url=base_url
        )
        
        # 定义时间解析提示模板
        self.parser_template = ChatPromptTemplate.from_template("""
        你是一个专门解析时间描述的AI助手。请从以下查询中提取时间范围描述，并将其转换为精确的起始时间和结束时间。
        
        当前时间: {current_time}
        用户查询: {query}
        
        首先，识别查询中的时间范围描述（如"前8小时"、"昨天"、"上周五到本周一"等）。
        然后，基于当前时间将其转换为具体的日期时间格式。
        
        请以JSON格式返回结果，包含以下字段：
        1. start_time: 起始时间，格式为"YYYY-MM-DD HH:MM:SS"
        2. end_time: 结束时间，格式为"YYYY-MM-DD HH:MM:SS"
        3. description: 对时间范围的简短描述
        4. formatted_range: 格式化的时间范围描述
        
        如果查询中没有明确的时间范围，请使用当前时间作为结束时间，当前时间前24小时作为起始时间。
        
        仅返回JSON格式的结果，不要有其他文字。
        """)
        
        # 创建解析器
        self.output_parser = JsonOutputParser()
        
        # 构建链
        self.chain = self.parser_template | self.llm | self.output_parser
    
    async def parse_time_range(self, query):
        """解析时间范围"""
        # 获取当前时间
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        logger.info(f"解析查询中的时间范围: {query}")
        
        # 调用链处理查询
        try:
            result = await self.chain.ainvoke({
                "query": query,
                "current_time": current_time
            })
            
            logger.info(f"时间范围解析成功: {result}")
            return result
        except Exception as e:
            logger.error(f"时间范围解析失败: {e}")
            # 如果解析失败，返回默认时间范围
            end_time = datetime.now()
            start_time = end_time - timedelta(hours=24)
            
            default_result = {
                "start_time": start_time.strftime("%Y-%m-%d %H:%M:%S"),
                "end_time": end_time.strftime("%Y-%m-%d %H:%M:%S"),
                "description": "默认时间范围（最近24小时）",
                "formatted_range": f"{start_time.strftime('%Y-%m-%d %H:%M:%S')} 至 {end_time.strftime('%Y-%m-%d %H:%M:%S')}",
                "error": str(e)
            }
            
            return default_result 