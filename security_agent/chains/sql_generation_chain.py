"""
SQL生成链 - 负责生成和执行SQL查询
"""
import logging
import re
from typing import Dict, Any, Optional, List

from langchain.chains import create_sql_query_chain
from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.runnables import RunnablePassthrough
from langchain_openai import ChatOpenAI
from langchain_community.utilities import SQLDatabase
from langchain_community.tools.sql_database.tool import QuerySQLDataBaseTool

logger = logging.getLogger(__name__)

class SQLGenerationChain:
    """SQL生成链，负责生成和执行SQL查询"""
    
    def __init__(
        self, 
        api_key: str, 
        db_connection: str,
        model_name: str = "qwen-plus", 
        base_url: str = "https://dashscope.aliyuncs.com/compatible-mode/v1",
        temperature: float = 0
    ):
        """初始化SQL生成链
        
        Args:
            api_key: API密钥
            db_connection: 数据库连接字符串
            model_name: 模型名称
            base_url: API基础URL
            temperature: 温度参数
        """
        logger.info("初始化SQL生成链")
        
        # 初始化LLM
        self.llm = ChatOpenAI(
            api_key=api_key,
            model_name=model_name,
            base_url=base_url,
            temperature=temperature
        )
        
        # 初始化数据库连接
        self.db = SQLDatabase.from_uri(db_connection)
        
        # 创建SQL查询工具
        self.execute_query_tool = QuerySQLDataBaseTool(db=self.db)
        
        # 创建SQL查询链
        self.sql_chain = create_sql_query_chain(self.llm, self.db)
    
    def _extract_sql(self, sql_text: str) -> str:
        """从LLM输出中提取实际的SQL查询
        
        Args:
            sql_text: 包含SQL查询的文本
            
        Returns:
            提取出的SQL查询
        """
        logger.info(f"提取SQL查询，原始文本: {sql_text[:100]}...")
        
        # 尝试提取SQL代码块
        sql_pattern = r"```sql\s*(.*?)\s*```"
        matches = re.search(sql_pattern, sql_text, re.DOTALL)
        if matches:
            return matches.group(1).strip()
        
        # 尝试提取SQLQuery标记后的内容
        if "SQLQuery:" in sql_text:
            parts = sql_text.split("SQLQuery:")
            if len(parts) > 1:
                # 检查是否有代码块
                code_matches = re.search(r"```\s*(.*?)\s*```", parts[1], re.DOTALL)
                if code_matches:
                    return code_matches.group(1).strip()
                # 否则取整个内容
                return parts[1].strip()
        
        # 如果没有特定标记，返回原始文本
        return sql_text
    
    def _extract_columns_from_query(self, query: str) -> List[str]:
        """从SQL查询中提取列名
        
        Args:
            query: SQL查询
            
        Returns:
            提取出的列名列表
        """
        logger.info("从SQL查询中提取列名")
        
        # 尝试提取SELECT子句中的列
        select_pattern = r"SELECT\s+(.*?)\s+FROM"
        matches = re.search(select_pattern, query, re.IGNORECASE | re.DOTALL)
        
        if not matches:
            return []
            
        select_clause = matches.group(1)
        
        # 处理*的情况
        if select_clause.strip() == '*':
            return []
            
        # 分割列
        columns = []
        current_column = ""
        parenthesis_level = 0
        
        for char in select_clause:
            if char == '(' and not (current_column.endswith("'") and not current_column.endswith("\\'")):
                parenthesis_level += 1
                current_column += char
            elif char == ')' and not (current_column.endswith("'") and not current_column.endswith("\\'")):
                parenthesis_level -= 1
                current_column += char
            elif char == ',' and parenthesis_level == 0:
                columns.append(current_column.strip())
                current_column = ""
            else:
                current_column += char
                
        if current_column:
            columns.append(current_column.strip())
            
        # 处理别名
        processed_columns = []
        for col in columns:
            # 处理AS别名
            as_match = re.search(r"(?i)(.+?)\s+AS\s+['\"]?([^'\"]+)['\"]?", col)
            if as_match:
                processed_columns.append(as_match.group(2).strip())
                continue
                
            # 处理空格别名
            space_match = re.search(r"(.+?)\s+['\"]?([^'\"]+)['\"]?$", col)
            if space_match and ' ' in col and not col.startswith('"') and not col.startswith("'"):
                processed_columns.append(space_match.group(2).strip())
                continue
                
            # 移除引号
            col = col.strip('"\'')
            
            # 处理函数调用
            func_match = re.search(r"(\w+)\(.*\)(?:\s+(?:as\s+)?['\"]?([^'\"]+)['\"]?)?$", col, re.IGNORECASE)
            if func_match:
                alias = func_match.group(2) if func_match.group(2) else func_match.group(1)
                processed_columns.append(alias.strip())
                continue
                
            # 处理普通列名
            processed_columns.append(col.split('.')[-1].strip())
            
        return processed_columns
    
    def _enhance_security_question(self, question: str) -> str:
        """增强安全相关问题，确保查询包含关键字段
        
        Args:
            question: 原始问题
            
        Returns:
            增强后的问题
        """
        # 检测是否是关于安全风险或攻击的模糊查询
        risk_terms = ["风险", "攻击", "威胁", "安全", "入侵", "异常", "可疑"]
        is_risk_query = any(term in question for term in risk_terms)
        
        if is_risk_query:
            # 检查问题是否已经包含字段信息
            field_terms = ["字段", "显示", "包含", "src_ip", "dst_ip", "threat_level", "源IP", "目标IP", "威胁等级"]
            has_field_info = any(term in question for term in field_terms)
            
            if not has_field_info:
                # 如果是模糊的风险查询且没有指定字段，增强问题以包含关键字段
                enhanced = question
                enhanced += "，请查询包含事件时间(event_time)、威胁等级(threat_level)、攻击类别(category)、源IP地址(src_ip)、目标IP地址(dst_ip)、攻击特征(signature)等关键安全信息"
                logger.info(f"增强后的问题: {enhanced}")
                return enhanced
        
        return question
    
    def generate_sql(self, question: str, table_names: Optional[List[str]] = None) -> str:
        """生成SQL查询，并确保包含关键安全分析字段
        
        Args:
            question: 用户问题
            table_names: 要使用的表名列表
        
        Returns:
            生成的SQL查询
        """
        logger.info(f"生成SQL查询，问题: {question}")
        
        # 增强问题，确保查询包含关键字段
        enhanced_question = self._enhance_security_question(question)
        
        inputs = {"question": enhanced_question}
        if table_names:
            inputs["table_names_to_use"] = table_names
            
        try:
            sql_query = self.sql_chain.invoke(inputs)
            logger.info(f"SQL查询生成成功: {sql_query[:100]}...")
            return sql_query
        except Exception as e:
            logger.error(f"SQL查询生成失败: {e}")
            raise
    
    def execute_sql(self, sql_query: str) -> str:
        """执行SQL查询
        
        Args:
            sql_query: SQL查询语句
        
        Returns:
            查询结果
        """
        logger.info(f"执行SQL查询: {sql_query[:100]}...")
        
        try:
            # 提取实际的SQL语句
            clean_sql = self._extract_sql(sql_query)
            logger.info(f"提取的SQL查询: {clean_sql[:100]}...")
            
            # 执行查询
            result = self.execute_query_tool.invoke(clean_sql)
            return result
        except Exception as e:
            logger.error(f"SQL查询执行失败: {e}")
            raise
    
    def get_table_info(self, table_names: Optional[List[str]] = None) -> str:
        """获取表信息
        
        Args:
            table_names: 表名列表
        
        Returns:
            表信息
        """
        return self.db.get_table_info(table_names)
    
    def get_usable_table_names(self) -> List[str]:
        """获取可用表名列表
        
        Returns:
            可用表名列表
        """
        return self.db.get_usable_table_names() 