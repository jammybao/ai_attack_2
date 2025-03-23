"""
官方SQL查询链 - 使用 LangChain 0.3 官方方法
整合SQL生成链和安全分析链
"""
import logging
from typing import Dict, Any, Optional, List, Tuple

from langchain_core.runnables import RunnablePassthrough

from security_agent.chains.sql_generation_chain import SQLGenerationChain
from security_agent.chains.security_analysis_chain import SecurityAnalysisChain

logger = logging.getLogger(__name__)

class OfficialSQLChain:
    """使用LangChain官方方法的SQL查询链，整合SQL生成和安全分析功能"""
    
    def __init__(
        self, 
        api_key: str, 
        db_connection: str,
        model_name: str = "qwen-plus", 
        base_url: str = "https://dashscope.aliyuncs.com/compatible-mode/v1",
        temperature: float = 0,
        ml_chain = None
    ):
        """初始化官方SQL查询链
        
        Args:
            api_key: API密钥
            db_connection: 数据库连接字符串
            model_name: 模型名称
            base_url: API基础URL
            temperature: 温度参数
            ml_chain: 机器学习安全链实例，可选
        """
        logger.info("初始化官方SQL查询链")
        
        # 初始化SQL生成链
        self.sql_generation_chain = SQLGenerationChain(
            api_key=api_key,
            db_connection=db_connection,
            model_name=model_name,
            base_url=base_url,
            temperature=temperature
        )
        
        # 初始化安全分析链
        self.security_analysis_chain = SecurityAnalysisChain(
            api_key=api_key,
            model_name=model_name,
            base_url=base_url,
            temperature=temperature,
            ml_chain=ml_chain
        )
        
        # 保存机器学习链引用
        self.ml_chain = ml_chain
        
        # 最后一次分析是否使用了机器学习增强
        self.last_ml_enhanced = False
        
        # 创建完整的查询和回答链
        self.query_and_answer_chain = self._create_query_and_answer_chain()
    
    def _create_query_and_answer_chain(self):
        """创建完整的查询和回答链"""
        def _process_inputs(inputs):
            question = inputs["question"]
            table_names = inputs.get("table_names_to_use")
            
            # 生成SQL查询
            sql_query = self.sql_generation_chain.generate_sql(question, table_names)
            
            # 执行SQL查询
            result = self.sql_generation_chain.execute_sql(sql_query)
            
            return {
                "question": question,
                "query": sql_query,
                "result": result
            }
        
        def _analyze_results(inputs):
            # 使用安全分析链分析结果
            return self.security_analysis_chain.analyze_security_data(
                inputs["question"],
                inputs["query"],
                inputs["result"]
            )
        
        return (
            RunnablePassthrough.assign(processed=_process_inputs)
            | (lambda x: _analyze_results(x["processed"]))
        )
    
    def _extract_columns_from_query(self, query: str) -> List[str]:
        """从SQL查询中提取列名，转发到SQL生成链
        
        Args:
            query: SQL查询
            
        Returns:
            提取出的列名列表
        """
        return self.sql_generation_chain._extract_columns_from_query(query)
    
    def _extract_sql(self, sql_text: str) -> str:
        """从LLM输出中提取实际的SQL查询，转发到SQL生成链
        
        Args:
            sql_text: 包含SQL查询的文本
            
        Returns:
            提取出的SQL查询
        """
        return self.sql_generation_chain._extract_sql(sql_text)
    
    def generate_sql(self, question: str, table_names: Optional[List[str]] = None) -> str:
        """生成SQL查询
        
        Args:
            question: 用户问题
            table_names: 要使用的表名列表
        
        Returns:
            生成的SQL查询
        """
        return self.sql_generation_chain.generate_sql(question, table_names)
    
    def execute_sql(self, sql_query: str) -> str:
        """执行SQL查询
        
        Args:
            sql_query: SQL查询语句
        
        Returns:
            查询结果
        """
        return self.sql_generation_chain.execute_sql(sql_query)
    
    def query_and_answer(
        self, 
        question: str, 
        use_ml: bool = True
    ) -> Dict[str, Any]:
        """执行查询并返回结果和安全分析
        
        Args:
            question: 用户问题
            use_ml: 是否使用机器学习安全分析
            
        Returns:
            包含查询、结果和安全分析的字典
        """
        logger.info(f"执行查询: {question}")
        
        # 步骤1: 生成SQL查询
        sql_query = self.generate_sql(question)
        logger.info(f"生成的SQL查询: {sql_query}")
        
        # 步骤2: 执行查询
        result = None
        try:
            result = self.execute_sql(sql_query)
            logger.info("SQL查询执行成功")
        except Exception as e:
            logger.error(f"SQL查询执行失败: {e}")
            result = f"查询执行失败: {str(e)}"
        
        # 步骤3: 安全分析
        security_analysis = None
        try:
            if self.security_analysis_chain:
                security_analysis = self.security_analysis_chain.analyze(
                    question=question,
                    sql_query=sql_query,
                    sql_result=result,
                    use_ml=use_ml and self.ml_chain is not None
                )
                logger.info("安全分析完成")
        except Exception as e:
            logger.error(f"安全分析失败: {e}")
            security_analysis = {
                "error": f"安全分析失败: {str(e)}",
                "risk_level": "未知"
            }
        
        # 构建返回结果
        answer = {
            "question": question,
            "sql_query": sql_query,
            "sql_result": result,
            "security_analysis": security_analysis
        }
        
        return answer
    
    def _format_analysis_result(self, analysis: Dict[str, Any]) -> str:
        """将结构化分析结果格式化为可读文本
        
        Args:
            analysis: 结构化分析结果
            
        Returns:
            格式化的分析文本
        """
        # 构建格式化输出
        output = f"## 安全分析结果\n\n"
        
        # 添加风险等级
        risk_level = analysis.get('risk_level', '未知')
        output += f"**风险等级**: {risk_level}\n\n"
        
        # 添加关键发现
        output += "### 关键发现\n\n"
        for finding in analysis.get('key_findings', []):
            output += f"- {finding}\n"
        output += "\n"
        
        # 添加安全建议
        output += "### 安全建议\n\n"
        for recommendation in analysis.get('recommendations', []):
            output += f"- {recommendation}\n"
        output += "\n"
        
        # 添加详细分析
        if analysis.get('details'):
            output += f"### 详细分析\n\n{analysis.get('details')}\n"
        
        return output
    
    def get_table_info(self, table_names: Optional[List[str]] = None) -> str:
        """获取表信息
        
        Args:
            table_names: 表名列表
        
        Returns:
            表信息
        """
        return self.sql_generation_chain.get_table_info(table_names)
    
    def get_usable_table_names(self) -> List[str]:
        """获取可用表名列表
        
        Returns:
            可用表名列表
        """
        return self.sql_generation_chain.get_usable_table_names()

    def query_database(self, question: str, table_names: Optional[List[str]] = None) -> Tuple[str, str]:
        """查询数据库，返回SQL查询和结果
        
        Args:
            question: 用户问题
            table_names: 要使用的表名列表
        
        Returns:
            包含SQL查询和结果的元组
        """
        logger.info(f"查询数据库，问题: {question}")
        
        try:
            # 生成SQL查询
            sql_query = self.generate_sql(question, table_names)
            
            # 执行SQL查询
            result = self.execute_sql(sql_query)
            
            return sql_query, result
        except Exception as e:
            logger.error(f"查询数据库失败: {e}")
            raise