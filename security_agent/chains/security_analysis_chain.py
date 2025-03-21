"""
安全分析链 - 负责对SQL查询结果进行专业的网络安全分析
优化版本：减少token消耗，避免冗余回答
"""
import logging
from typing import Dict, Any, Optional, List, Literal

from langchain_core.output_parsers import JsonOutputParser
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.runnables import RunnableLambda
from langchain_openai import ChatOpenAI
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# 定义结构化输出模型
class SecurityAnalysisResult(BaseModel):
    """安全分析结果的结构化模型"""
    risk_level: Literal["高", "中", "低", "未知"] = Field(
        description="整体安全风险等级评估"
    )
    key_findings: List[str] = Field(
        description="关键安全发现，最多3项",
        max_items=3
    )
    recommendations: List[str] = Field(
        description="安全建议，最多3项",
        max_items=3
    )
    ip_analysis: Optional[str] = Field(
        description="IP分析结果，包括攻击源IP和目标IP的特征分析",
        default=None
    )
    ip_correlation: Optional[str] = Field(
        description="多条日志间的IP关联性分析结果",
        default=None
    )
    details: Optional[str] = Field(
        description="简要分析详情，不超过200字",
        max_length=200
    )

class SecurityAnalysisChain:
    """优化的安全分析链，负责对SQL查询结果进行专业的网络安全分析"""
    
    def __init__(
        self, 
        api_key: str,
        model_name: str = "qwen-plus", 
        base_url: str = "https://dashscope.aliyuncs.com/compatible-mode/v1",
        temperature: float = 0
    ):
        """初始化安全分析链
        
        Args:
            api_key: API密钥
            model_name: 模型名称
            base_url: API基础URL
            temperature: 温度参数
        """
        logger.info("初始化优化版安全分析链")
        
        # 初始化LLM
        self.llm = ChatOpenAI(
            api_key=api_key,
            model_name=model_name,
            base_url=base_url,
            temperature=temperature
        )
        
        # 创建分析链
        self.analysis_chain = self._create_analysis_chain()
    
    def _assess_query_complexity(self, query: str, result: str) -> str:
        """评估查询的复杂度
        
        Args:
            query: SQL查询
            result: 查询结果
            
        Returns:
            复杂度评级: "high", "medium", "low"
        """
        # 检查是否包含高风险指标
        high_risk_indicators = [
            "threat_level > 30", 
            "threat_level >= 40",
            "威胁等级 > 30",
            "威胁等级 >= 40"
        ]
        
        if any(indicator in query for indicator in high_risk_indicators):
            return "high"
            
        # 检查是否包含多个安全相关字段
        security_fields = [
            "src_ip", "dst_ip", "threat_level", 
            "attack_step", "attack_function", "category",
            "signature", "protocol"
        ]
        
        field_count = sum(1 for field in security_fields if field in query)
        
        if field_count >= 3:
            return "medium"
            
        # 检查结果大小
        try:
            # 尝试评估结果大小
            if len(result) > 500 or result.count('\n') > 10:
                return "medium"
        except:
            pass
            
        return "low"
    
    def _get_template_by_complexity(self, complexity: str, query: str) -> str:
        """根据复杂度获取适当的模板
        
        Args:
            complexity: 复杂度评级
            query: SQL查询
            
        Returns:
            提示词模板
        """
        # 基础模板部分
        base_template = """你是一位专业的网络安全分析师，精通入侵检测系统(IDS)数据分析。
请根据以下信息对安全事件进行简明扼要的分析:

用户问题: {question}
SQL查询: {query}
查询结果: {result}

"""
        
        # 根据复杂度添加分析指导
        if complexity == "high":
            # 高复杂度查询 - 添加详细分析指导，但保持简洁
            template = base_template + """请重点分析以下方面:
"""
            # 根据查询内容动态添加分析维度
            if "src_ip" in query or "dst_ip" in query:
                template += """- 网络流量：识别可能的攻击源IP和受害目标IP，检查异常通信模式
- IP分析：分析攻击源IP的地理位置、信誉度和历史行为模式
- IP关联性：分析多条日志中是否存在相同的攻击源IP或目标IP，识别可能的攻击活动关联
"""
            
            if "threat_level" in query:
                template += """- 威胁评估：重点关注高威胁等级(30-40)事件，评估整体安全态势
"""
                
            if "attack_step" in query or "attack_function" in query or "category" in query:
                template += """- 攻击分析：识别攻击链和可能的攻击意图，评估攻击的复杂性
"""
                
            if "signature" in query:
                template += """- 攻击特征：解读攻击特征的具体含义，评估误报可能性
"""
                
            # 添加MITRE ATT&CK关联提示
            template += """- MITRE关联：将观察到的攻击行为映射到MITRE ATT&CK框架中的相关技术
"""
                
        elif complexity == "medium":
            # 中等复杂度查询 - 添加基本分析指导
            template = base_template + """请对数据进行中等深度分析，关注主要安全模式和趋势。
重点识别潜在的安全风险，并提供针对性的安全建议。

请务必包含以下分析：
- IP分析：分析攻击源IP和目标IP的特征和行为模式
- IP关联性：分析多条日志中是否存在相同的IP，识别可能的关联攻击活动
"""
        else:
            # 低复杂度查询 - 最简化的分析指导
            template = base_template + """请对数据进行简要分析，提取关键安全信息。
如果数据不足以进行深入分析，请说明需要哪些额外信息。

即使数据有限，也请尝试分析：
- IP信息：任何可用的源IP和目标IP信息
- 可能的关联性：数据中是否有任何IP关联模式
"""
            
        # 添加输出格式要求
        template += """
请以JSON格式返回分析结果，包含以下字段:
- risk_level: 整体风险等级("高"/"中"/"低"/"未知")
- key_findings: 关键发现列表(最多3项)
- recommendations: 安全建议列表(最多3项)
- ip_analysis: IP分析结果，包括攻击源IP和目标IP的特征分析
- ip_correlation: 多条日志间的IP关联性分析结果
- details: 简要分析详情(不超过200字)

确保分析简明扼要，避免冗余内容。
"""
        return template
    
    def _create_analysis_chain(self):
        """创建优化的分析链，使用结构化输出和动态提示词"""
        
        def get_dynamic_template(inputs):
            """根据查询内容动态生成提示词模板"""
            query = inputs["query"]
            result = inputs["result"]
            
            # 评估查询复杂度
            complexity = self._assess_query_complexity(query, result)
            logger.info(f"查询复杂度评估: {complexity}")
            
            # 获取适当的模板
            template = self._get_template_by_complexity(complexity, query)
            
            return template
        
        # 创建动态提示词链
        def dynamic_prompt_chain(inputs):
            # 生成动态模板
            template = get_dynamic_template(inputs)
            prompt = ChatPromptTemplate.from_template(template)
            
            # 使用结构化输出解析器
            parser = JsonOutputParser(pydantic_object=SecurityAnalysisResult)
            
            # 构建链
            chain = prompt | self.llm | parser
            return chain.invoke(inputs)
        
        return RunnableLambda(dynamic_prompt_chain)
    
    def analyze_security_data(self, question: str, query: str, result: str) -> Dict[str, Any]:
        """分析安全数据
        
        Args:
            question: 用户问题
            query: SQL查询
            result: 查询结果
            
        Returns:
            安全分析结果(结构化)
        """
        logger.info(f"分析安全数据，问题: {question}")
        
        # 检查结果是否为空
        if not result or result.strip() == "" or result.strip() == "[]" or result.strip() == "()":
            logger.info("查询结果为空，返回无数据分析结果")
            return {
                "risk_level": "低",
                "key_findings": ["查询未返回任何数据", "在指定条件下没有发现安全事件", "当前时间范围内没有符合条件的威胁"],
                "recommendations": ["扩大查询时间范围", "降低威胁等级阈值", "检查数据收集系统是否正常工作"],
                "ip_analysis": "无法进行IP分析，因为查询未返回任何数据。",
                "ip_correlation": "无法进行IP关联性分析，因为查询未返回任何数据。",
                "details": "在指定的查询条件下未发现任何安全事件。这可能表示在该时间范围内没有高威胁事件。"
            }
        
        inputs = {
            "question": question,
            "query": query,
            "result": result
        }
        
        try:
            # 调用分析链获取结构化结果
            analysis = self.analysis_chain.invoke(inputs)
            logger.info("安全分析完成")
            return analysis
        except Exception as e:
            logger.error(f"安全分析失败: {e}")
            # 返回基本错误信息
            return {
                "risk_level": "未知",
                "key_findings": ["分析过程中发生错误"],
                "recommendations": ["请检查数据并重试分析"],
                "ip_analysis": "分析过程中发生错误，无法完成IP分析。",
                "ip_correlation": "分析过程中发生错误，无法完成IP关联性分析。",
                "details": f"错误信息: {str(e)[:100]}"
            }
    
    def format_analysis_result(self, analysis: Dict[str, Any]) -> str:
        """将结构化分析结果格式化为可读文本
        
        Args:
            analysis: 结构化分析结果
            
        Returns:
            格式化的分析文本
        """
        # 构建格式化输出
        output = f"## 安全分析结果\n\n"
        output += f"**风险等级**: {analysis.get('risk_level', '未知')}\n\n"
        
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
        
        # 添加IP分析
        if analysis.get('ip_analysis'):
            output += "### IP分析\n\n"
            output += f"{analysis.get('ip_analysis')}\n\n"
        
        # 添加IP关联性分析
        if analysis.get('ip_correlation'):
            output += "### IP关联性分析\n\n"
            output += f"{analysis.get('ip_correlation')}\n\n"
        
        # 添加详细分析
        if analysis.get('details'):
            output += f"### 详细分析\n\n{analysis.get('details')}\n"
        
        return output 