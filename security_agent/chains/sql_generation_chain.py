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
        """增强安全分析问题，确保包含关键字段
        
        Args:
            question: 原始问题
            
        Returns:
            增强后的问题
        """
        enhanced = question
        
        # 判断问题类型
        is_threat_query = any(term in question.lower() for term in ["威胁", "攻击", "告警", "alert", "threat", "attack"])
        is_high_risk_query = any(term in question.lower() for term in ["高危", "高风险", "严重", "紧急", "critical", "high"])
        is_ip_query = any(term in question.lower() for term in ["ip", "源ip", "目标ip", "流量", "通信"])
        focus_on_external_ip = any(term in question.lower() for term in ["外部", "外网", "互联网", "external"])
        
        # 调整查询以包含重要安全字段
        if is_threat_query:
            enhanced += "，请确保查询结果包含事件时间(event_time)、源IP(src_ip)、目标IP(dst_ip)、威胁等级(threat_level)和特征(signature)字段"
            
            # 如果是高危告警查询，明确指定威胁等级阈值
            if is_high_risk_query:
                enhanced += "，请确保查询条件中包含威胁等级(threat_level)>=30的条件，这是高危告警的定义标准"
        
        # 如果查询涉及IP分析，添加与ip_address表的关联
        if is_ip_query:
            enhanced += "，并且请使用LEFT JOIN关联ip_address表，以提供IP的network_type信息，这对区分内外部IP很重要。对于源IP，使用LEFT JOIN ip_address ON security_logs.src_ip = ip_address.ip，并在结果中包含ip_address.network_type字段"
            
            # 如果特别关注外部IP，提供明确的外部IP判断条件
            if focus_on_external_ip:
                enhanced += "。请注意，外部IP的判断条件是ip_address.network_type IS NULL，不是network_type不等于某个特定值。当查询外部IP时，请在WHERE条件中使用ip_address.network_type IS NULL作为筛选条件"
                
        # 如果同时关注高风险事件和外部IP，使用OR逻辑连接两个条件
        if is_high_risk_query and focus_on_external_ip:
            enhanced += "。注意：当同时查询高风险事件和外部IP时，请使用OR逻辑连接这两个条件(threat_level >= 30 OR ip_address.network_type IS NULL)，而不是AND逻辑，以确保能够获取两种情况的事件"
        
        logger.info(f"增强后的问题: {enhanced}")
        return enhanced
    
    def enhance_prompt(self, user_question: str) -> str:
        """增强问题提示，添加更多细节和上下文
        
        Args:
            user_question: 用户原始问题
            
        Returns:
            增强后的问题提示
        """
        enhanced_prompt = f"{user_question}，请确保查询结果包含事件时间(event_time)、源IP(src_ip)、目标IP(dst_ip)、威胁等级(threat_level)和特征(signature)字段，"
        
        # 添加关于高危告警的提示
        enhanced_prompt += "请确保查询条件中包含威胁等级(threat_level)>=30的条件，这是高危告警的定义标准，"
        
        # 添加关于内外部IP的提示
        enhanced_prompt += "并且请使用LEFT JOIN关联ip_address表，以提供IP的network_type信息，这对区分内外部IP很重要。"
        enhanced_prompt += "对于源IP，使用LEFT JOIN ip_address ON security_logs.src_ip = ip_address.ip，并在结果中包含ip_address.network_type字段。"
        
        # 添加明确的内外部IP字段定义
        enhanced_prompt += "请添加一个明确的字段：CASE WHEN ip_address.network_type IS NULL THEN 'external' ELSE 'internal' END AS ip_type，"
        enhanced_prompt += "以便直接标识该IP是内部IP还是外部IP。"
        
        # 添加外部IP的明确定义
        enhanced_prompt += "请注意，外部IP的判断条件是ip_address.network_type IS NULL，不是network_type不等于某个特定值。"
        enhanced_prompt += "当查询外部IP时，请在WHERE条件中使用ip_address.network_type IS NULL作为筛选条件。"
        
        # 添加高风险事件和外部IP的逻辑关系提示
        enhanced_prompt += "注意：当同时查询高风险事件和外部IP时，请使用OR逻辑连接这两个条件(threat_level >= 30 OR ip_address.network_type IS NULL)，而不是AND逻辑，以确保能够获取两种情况的事件"
        
        return enhanced_prompt
    
    def generate_sql(self, question: str, table_names: Optional[List[str]] = None) -> str:
        """生成SQL查询，并确保包含关键安全分析字段
        
        Args:
            question: 用户问题
            table_names: 要使用的表名列表
        
        Returns:
            生成的SQL查询
        """
        logger.info(f"生成SQL查询，问题: {question}")
        
        # 增强问题，确保查询包含关键字段和ip_type字段
        enhanced_question = self.enhance_prompt(question)
        
        inputs = {"question": enhanced_question}
        if table_names:
            # 确保ip_address表在表名列表中，如果涉及IP分析
            if any(term in question.lower() for term in ["ip", "源ip", "目标ip", "内部", "外部", "入侵"]):
                if "ip_address" not in table_names:
                    table_names.append("ip_address")
            inputs["table_names_to_use"] = table_names
            
        try:
            sql_query = self.sql_chain.invoke(inputs)
            logger.info(f"SQL查询生成成功: {sql_query[:100]}...")
            
            # 检查是否是高危告警查询，直接修改生成的SQL
            high_risk_terms = ["高危", "高风险", "严重", "紧急", "critical", "high"]
            is_high_risk_query = any(term in question for term in high_risk_terms)
            
            if is_high_risk_query:
                # 提取SQL语句
                clean_sql = self._extract_sql(sql_query)
                
                # 检查是否已包含高危告警条件
                high_threat_conditions = ["threat_level >= 30", "threat_level > 30", "threat_level >= 40"]
                has_high_threat_condition = any(condition in clean_sql for condition in high_threat_conditions)
                
                if not has_high_threat_condition:
                    # 如果不包含，添加高危条件
                    if "WHERE" in clean_sql:
                        # 已有WHERE子句，添加AND条件
                        modified_sql = clean_sql.replace("WHERE", "WHERE threat_level >= 30 AND ")
                    else:
                        # 没有WHERE子句，添加新的WHERE子句
                        modified_sql = clean_sql + " WHERE threat_level >= 30"
                    
                    # 将修改后的SQL放回原始响应格式
                    if "```sql" in sql_query:
                        sql_query = sql_query.replace(clean_sql, modified_sql)
                    else:
                        sql_query = modified_sql
            
            # 确保SQL查询包含ip_type字段
            clean_sql = self._extract_sql(sql_query)
            if "ip_type" not in clean_sql and ("src_ip" in clean_sql or "source_ip" in clean_sql):
                modified_sql = self._ensure_ip_type_field(clean_sql)
                
                # 将修改后的SQL放回原始响应格式
                if "```sql" in sql_query:
                    sql_query = sql_query.replace(clean_sql, modified_sql)
                else:
                    sql_query = modified_sql
            
            # 移除LIMIT限制
            clean_sql = self._extract_sql(sql_query)
            if "LIMIT" in clean_sql:
                # 使用正则表达式移除LIMIT子句
                modified_sql = re.sub(r'\s+LIMIT\s+\d+\s*;?', ';', clean_sql)
                
                # 确保SQL语句以分号结尾
                if not modified_sql.strip().endswith(';'):
                    modified_sql = modified_sql.strip() + ';'
                
                # 将修改后的SQL放回原始响应格式
                if "```sql" in sql_query:
                    sql_query = sql_query.replace(clean_sql, modified_sql)
                else:
                    sql_query = modified_sql
                    
                logger.info(f"移除了LIMIT限制，修改后的SQL: {modified_sql[:100]}...")
            
            return sql_query
        except Exception as e:
            logger.error(f"SQL查询生成失败: {e}")
            raise
    
    def _ensure_ip_type_field(self, sql: str) -> str:
        """确保SQL查询包含ip_type字段
        
        Args:
            sql: 原始SQL查询
            
        Returns:
            添加了ip_type字段的SQL查询
        """
        # 检查是否已经包含ip_type字段
        if "ip_type" in sql:
            return sql
            
        # 提取SELECT和FROM部分
        select_pattern = r"(SELECT\s+)(.*?)(\s+FROM\s+)(.*?)(\s+WHERE|\s+GROUP BY|\s+ORDER BY|\s*$)"
        match = re.search(select_pattern, sql, re.IGNORECASE | re.DOTALL)
        
        if not match:
            return sql
            
        select_keyword = match.group(1)
        select_fields = match.group(2)
        from_keyword = match.group(3)
        from_tables = match.group(4)
        rest_of_query = match.group(5)
        
        # 判断是否包含ip_address表
        if "ip_address" not in from_tables:
            # 需要先添加ip_address表的关联
            sql = self._add_ip_address_join(sql)
            return self._ensure_ip_type_field(sql)  # 递归调用，确保添加ip_type字段
        
        # 提取表别名
        ip_address_alias_match = re.search(r"ip_address\s+(?:as\s+)?([a-zA-Z0-9_]+)", from_tables, re.IGNORECASE)
        alias = ip_address_alias_match.group(1) if ip_address_alias_match else "ip_address"
        
        # 添加ip_type字段
        ip_type_field = f", CASE WHEN {alias}.network_type IS NULL THEN 'external' ELSE 'internal' END AS ip_type"
        
        # 处理SELECT部分
        if select_fields.strip() == "*":
            select_fields = f"*, {ip_type_field}"
        else:
            select_fields = f"{select_fields}{ip_type_field}"
        
        # 重建SQL查询
        modified_sql = f"{select_keyword}{select_fields}{from_keyword}{from_tables}{rest_of_query}"
        
        logger.info(f"添加了ip_type字段的SQL: {modified_sql[:100]}...")
        return modified_sql
    
    def _add_ip_address_join(self, sql: str) -> str:
        """添加与ip_address表的关联查询
        
        Args:
            sql: 原始SQL查询
            
        Returns:
            添加了ip_address表关联的SQL查询
        """
        # 检查是否已经包含ip_address表
        if "ip_address" in sql:
            return sql
            
        # 提取SELECT和FROM部分
        select_pattern = r"(SELECT\s+)(.*?)(\s+FROM\s+)(.*?)(\s+WHERE|\s+GROUP BY|\s+ORDER BY|\s*$)"
        match = re.search(select_pattern, sql, re.IGNORECASE | re.DOTALL)
        
        if not match:
            return sql
            
        select_keyword = match.group(1)
        select_fields = match.group(2)
        from_keyword = match.group(3)
        from_tables = match.group(4)
        rest_of_query = match.group(5)
        
        # 判断主表名
        main_table = from_tables.strip()
        table_alias = ""
        
        # 检查是否有表别名
        if " as " in main_table.lower() or " " in main_table:
            parts = re.split(r"\s+as\s+|\s+", main_table, 1, re.IGNORECASE)
            main_table = parts[0]
            table_alias = parts[1] if len(parts) > 1 else ""
        
        # 添加network_type字段到SELECT部分
        if select_fields.strip() == "*":
            # 处理SELECT *的情况
            select_fields = f"{main_table}.*, src_ip_info.network_type AS src_network_type, dst_ip_info.network_type AS dst_network_type"
        else:
            # 添加到已有字段后面
            select_fields = f"{select_fields}, src_ip_info.network_type AS src_network_type, dst_ip_info.network_type AS dst_network_type"
        
        # 构建新的FROM部分，添加LEFT JOIN
        prefix = table_alias if table_alias else main_table
        new_from = f"{from_tables} LEFT JOIN ip_address AS src_ip_info ON {prefix}.src_ip = src_ip_info.ip LEFT JOIN ip_address AS dst_ip_info ON {prefix}.dst_ip = dst_ip_info.ip"
        
        # 重建SQL查询
        modified_sql = f"{select_keyword}{select_fields}{from_keyword}{new_from}{rest_of_query}"
        
        logger.info(f"添加了ip_address表关联的SQL: {modified_sql[:100]}...")
        return modified_sql
    
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