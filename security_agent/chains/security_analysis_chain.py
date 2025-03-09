"""
安全分析链 - 负责对SQL查询结果进行专业的网络安全分析
"""
import logging
from typing import Dict, Any, Optional, List

from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.runnables import RunnableLambda
from langchain_openai import ChatOpenAI

logger = logging.getLogger(__name__)

class SecurityAnalysisChain:
    """安全分析链，负责对SQL查询结果进行专业的网络安全分析"""
    
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
        logger.info("初始化安全分析链")
        
        # 初始化LLM
        self.llm = ChatOpenAI(
            api_key=api_key,
            model_name=model_name,
            base_url=base_url,
            temperature=temperature
        )
        
        # 创建分析链
        self.analysis_chain = self._create_analysis_chain()
    
    def _create_analysis_chain(self):
        """创建分析链，使用动态提示词模板"""
        
        def get_dynamic_template(inputs):
            """根据查询结果动态生成提示词模板"""
            question = inputs["question"]
            query = inputs["query"]
            result = inputs["result"]
            
            # 基础模板
            template = """你是一位专业的网络安全分析师，精通入侵检测系统(IDS)数据分析。请根据以下信息对安全事件进行专业分析:

用户问题: {question}
SQL查询: {query}
查询结果: {result}

"""
            
            # 分析查询结果中包含的字段
            has_ip_info = "src_ip" in query or "source_ip" in query or "dst_ip" in query or "destination_ip" in query
            has_threat_level = "threat_level" in query
            has_attack_info = "attack_step" in query or "attack_function" in query or "category" in query
            has_event_time = "event_time" in query
            has_protocol = "protocol" in query
            has_signature = "signature" in query
            has_traffic_data = "bytes_to_server" in query or "bytes_to_client" in query or "packets_to_server" in query or "packets_to_client" in query
            
            # 检测是否是关于安全风险的查询
            risk_terms = ["风险", "攻击", "威胁", "安全", "入侵", "异常", "可疑"]
            is_risk_query = any(term in question for term in risk_terms)
            
            # 添加专业分析指导
            template += """## 分析要点

请对查询结果进行全面的安全分析，包括但不限于以下方面:
"""
            
            if has_ip_info:
                template += """
### 网络流量分析
- 识别可能的攻击源IP和受害目标IP
- 检查是否有重复出现的IP地址（可能表示持续攻击）
- 分析内部网络与外部网络的交互模式
- 评估是否存在可疑的地理位置来源（如已知的威胁活动区域）
- 检查是否有异常的IP通信模式（如扫描行为、数据外泄等）
"""
            
            if has_threat_level:
                template += """
### 威胁等级评估
- 重点关注高威胁等级(4-5)的事件，这些通常表示严重安全问题
- 分析中等威胁等级(2-3)的事件模式，寻找潜在的攻击前兆
- 评估整体安全态势，包括威胁等级的分布和趋势
- 对高威胁事件进行优先级排序，提供紧急处理建议
"""
            
            if has_attack_info:
                template += """
### 攻击类型和战术分析
- 识别攻击链和可能的攻击意图（如数据窃取、系统破坏等）
- 评估攻击的复杂性和持久性
- 确定是否存在高级持续性威胁(APT)的迹象
- 分析攻击者使用的技术、战术和程序(TTPs)
- 将观察到的攻击模式与已知威胁行为体(Threat Actors)进行对比
"""
            
            if has_event_time:
                template += """
### 时间模式分析
- 识别攻击的时间模式（如工作时间vs非工作时间）
- 检测攻击活动的频率和持续时间
- 分析事件的时间序列，识别攻击的各个阶段
- 评估是否存在与已知攻击活动相关的时间特征
"""
            
            if has_protocol:
                template += """
### 协议和服务分析
- 分析被攻击的网络协议和服务
- 识别常见的漏洞利用途径（如特定协议的已知漏洞）
- 评估是否存在协议异常或滥用
- 检查是否有针对特定服务的持续攻击尝试
"""
            
            if has_signature:
                template += """
### 攻击特征分析
- 解读攻击特征(signature)的具体含义
- 将特征与已知的攻击技术和漏洞进行关联
- 评估误报的可能性
- 分析特征的严重性和潜在影响
"""
            
            if has_traffic_data:
                template += """
### 流量数据分析
- 分析数据传输量是否异常（可能表示数据外泄）
- 检测异常的流量模式（如突发流量、持续小流量等）
- 评估客户端与服务器之间的流量不对称性
- 识别可能的命令与控制(C2)通信特征
"""
            
            # 如果是模糊的风险查询但缺少详细信息
            if is_risk_query and not (has_ip_info and has_threat_level and has_attack_info):
                template += """
### 有限数据分析
虽然查询结果可能不包含所有详细信息，请尽可能根据可用数据评估安全风险。
如果需要更详细的分析，建议扩展查询以包含更多关键安全字段，如源IP、目标IP、威胁等级、攻击类别等。
"""
            
            # 添加MITRE ATT&CK框架关联分析
            template += """
### MITRE ATT&CK关联
- 将观察到的攻击行为映射到MITRE ATT&CK框架中的战术和技术
- 识别可能的攻击阶段（如初始访问、横向移动、数据外泄等）
- 提供相关的ATT&CK技术ID和名称（如T1190-漏洞利用面向公众的应用程序）
"""
            
            # 添加安全建议部分
            template += """
## 安全建议

根据分析结果，请提供具体的安全建议，包括:
- 紧急缓解措施（如阻断特定IP、关闭受影响服务等）
- 中期防御策略（如更新安全规则、加强监控等）
- 长期安全加固建议（如架构改进、安全培训等）
- 建议的进一步调查方向

## 总结

请提供简明扼要的总结，包括:
- 整体安全态势评估
- 最关键的安全发现
- 最优先的行动建议
"""
            
            return template
        
        # 创建动态提示词链
        def dynamic_prompt_chain(inputs):
            template = get_dynamic_template(inputs)
            prompt = ChatPromptTemplate.from_template(template)
            chain = prompt | self.llm | StrOutputParser()
            return chain.invoke(inputs)
        
        return RunnableLambda(dynamic_prompt_chain)
    
    def analyze_security_data(self, question: str, query: str, result: str) -> str:
        """分析安全数据
        
        Args:
            question: 用户问题
            query: SQL查询
            result: 查询结果
            
        Returns:
            安全分析结果
        """
        logger.info(f"分析安全数据，问题: {question}")
        
        inputs = {
            "question": question,
            "query": query,
            "result": result
        }
        
        try:
            analysis = self.analysis_chain.invoke(inputs)
            logger.info("安全分析完成")
            return analysis
        except Exception as e:
            logger.error(f"安全分析失败: {e}")
            raise 