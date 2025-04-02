"""
安全分析链 - 负责对SQL查询结果进行专业的网络安全分析
优化版本：减少token消耗，避免冗余回答
"""
import logging
import re
from typing import Dict, Any, Optional, List, Literal, Tuple
import pandas as pd
import json

from langchain_core.output_parsers import JsonOutputParser
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.runnables import RunnableLambda
from langchain_openai import ChatOpenAI
from pydantic import BaseModel, Field

from security_agent.chains.ml_security_chain import MLSecurityChain

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
        temperature: float = 0,
        ml_chain: Optional[MLSecurityChain] = None
    ):
        """初始化安全分析链
        
        Args:
            api_key: API密钥
            model_name: 模型名称
            base_url: API基础URL
            temperature: 温度参数
            ml_chain: 机器学习安全链实例，可选
        """
        logger.info("初始化优化版安全分析链")
        
        # 初始化LLM
        self.llm = ChatOpenAI(
            api_key=api_key,
            model_name=model_name,
            base_url=base_url,
            temperature=temperature
        )
        
        # 机器学习安全链
        self.ml_chain = ml_chain
        
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
    
    def _analyze_ip_addresses(self, sql_result: str) -> Dict[str, Any]:
        """分析IP地址信息
        
        Args:
            sql_result: SQL查询结果
            
        Returns:
            IP地址分析结果
        """
        # 使用正则表达式从结果中提取IP地址
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        all_ips = re.findall(ip_pattern, sql_result)
        
        if not all_ips:
            return {
                "total_ips_found": 0,
                "unique_ips": [],
                "frequent_ips": [],
                "internal_ips": [],
                "external_ips": []
            }
            
        # 计算每个IP出现的次数
        ip_counts = {}
        for ip in all_ips:
            ip_counts[ip] = ip_counts.get(ip, 0) + 1
            
        # 提取内部和外部IP
        internal_ips = []
        external_ips = []
        
        # 检查SQL结果中是否包含网络类型信息
        network_type_pattern = r'(\b(?:\d{1,3}\.){3}\d{1,3}\b).*?network_type[\'"]?\s*[=:]?\s*[\'"]?([^\'",\s]*)'
        ip_network_matches = re.findall(network_type_pattern, sql_result, re.IGNORECASE)
        
        # 创建IP到网络类型的映射
        ip_network_map = {}
        if ip_network_matches:
            for ip, network_type in ip_network_matches:
                # 修改判断逻辑：只有当network_type不为NULL和空值时，才视为内部IP
                if network_type and network_type.lower() not in ['null', 'none', '']:
                    ip_network_map[ip] = network_type
                    internal_ips.append((ip, network_type))
                else:
                    # network_type为NULL的IP视为外部IP
                    external_ips.append(ip)
                
            # 将未在映射中的IP视为外部IP（这些是不在ip_address表中的IP）
            for ip in ip_counts:
                if ip not in ip_network_map and ip not in external_ips:
                    external_ips.append(ip)
        else:
            # 如果没有网络类型信息，则将所有IP视为外部IP
            external_ips = list(ip_counts.keys())
        
        # 获取出现频率最高的IP
        sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)
        frequent_ips = [(ip, count) for ip, count in sorted_ips[:5]]
            
        return {
            "total_ips_found": len(all_ips),
            "unique_ips": list(ip_counts.keys()),
            "frequent_ips": frequent_ips,
            "internal_ips": internal_ips,
            "external_ips": external_ips
        }
    
    def analyze(self, question: str, sql_query: str, sql_result: str, use_ml: bool = True) -> Dict[str, Any]:
        """分析SQL查询结果，提取安全信息
        
        Args:
            question: 原始问题
            sql_query: 生成的SQL查询
            sql_result: SQL查询结果
            use_ml: 是否使用机器学习增强分析
            
        Returns:
            安全分析结果
        """
        logger.info(f"开始分析SQL查询结果，{'启用' if use_ml and self.ml_chain else '不启用'}机器学习增强")
        
        # 基础分析
        analysis_result = {
            "risk_level": "低",  # 默认风险等级
            "key_findings": [],  # 关键发现
            "recommendations": [],  # 安全建议
            "detailed_analysis": ""  # 详细分析
        }
        
        # 分析IP地址
        ip_analysis = self._analyze_ip_addresses(sql_result)
        
        if ip_analysis["total_ips_found"] > 0:
            # 准备IP分析文本
            ip_text = f"分析发现{ip_analysis['total_ips_found']}个IP地址，其中唯一IP有{len(ip_analysis['unique_ips'])}个。"
            
            # 添加内部/外部IP分类信息
            if ip_analysis["internal_ips"]:
                ip_text += f"\n- 内部IP: {len(ip_analysis['internal_ips'])}个"
                for ip, network_type in ip_analysis["internal_ips"][:5]:
                    ip_text += f"\n  * {ip} (网络类型: {network_type})"
                if len(ip_analysis["internal_ips"]) > 5:
                    ip_text += f"\n  * ...等{len(ip_analysis['internal_ips'])}个"
                    
            if ip_analysis["external_ips"]:
                ip_text += f"\n- 外部IP: {len(ip_analysis['external_ips'])}个"
                for ip in ip_analysis["external_ips"][:5]:
                    ip_text += f"\n  * {ip}"
                if len(ip_analysis["external_ips"]) > 5:
                    ip_text += f"\n  * ...等{len(ip_analysis['external_ips'])}个"
                    
            # 添加高频IP信息
            if ip_analysis["frequent_ips"]:
                ip_text += "\n\n出现频率最高的IP:"
                for ip, count in ip_analysis["frequent_ips"]:
                    is_internal = any(internal_ip[0] == ip for internal_ip in ip_analysis["internal_ips"])
                    ip_type = "内部" if is_internal else "外部"
                    network_type = ""
                    if is_internal:
                        for internal_ip, net_type in ip_analysis["internal_ips"]:
                            if internal_ip == ip:
                                network_type = f" (网络类型: {net_type})"
                                break
                    ip_text += f"\n- {ip}{network_type}: 出现{count}次 [{ip_type}]"
            
            analysis_result["ip_analysis"] = ip_text
            
            # 修改风险评级逻辑：若存在外部IP，直接将风险等级设置为"高"
            if ip_analysis["external_ips"]:
                analysis_result["risk_level"] = "高"
                analysis_result["key_findings"].append(f"发现外部IP({len(ip_analysis['external_ips'])}个)，存在潜在安全风险")
                analysis_result["recommendations"].append("立即审查外部IP通信记录，确认是否为授权通信或存在攻击行为")
            # 保留原有逻辑作为补充
            else:
                # 如果外部IP较多，增加风险评级
                external_ip_ratio = len(ip_analysis["external_ips"]) / (len(ip_analysis["unique_ips"]) or 1)
                if external_ip_ratio > 0.7 and len(ip_analysis["external_ips"]) > 3:
                    analysis_result["risk_level"] = "中"
                    analysis_result["key_findings"].append(f"发现大量外部IP({len(ip_analysis['external_ips'])}个)，可能存在外部通信")
                    analysis_result["recommendations"].append("建议审查外部IP通信记录，确认是否为授权通信")
        
        # 其他基础分析...
        if "error" in sql_result.lower() or "exception" in sql_result.lower():
            analysis_result["key_findings"].append("查询结果中包含错误或异常信息")
            analysis_result["risk_level"] = "中"
            
        if "attack" in sql_result.lower() or "exploit" in sql_result.lower():
            analysis_result["key_findings"].append("查询结果中包含攻击或漏洞利用相关信息")
            analysis_result["risk_level"] = "高"
            analysis_result["recommendations"].append("立即调查潜在的攻击活动")
            
        # 使用机器学习增强分析
        if use_ml and self.ml_chain:
            logger.info("使用机器学习增强安全分析")
            print("【调试】开始使用机器学习增强安全分析")
            print(f"【调试】ml_chain是否存在: {self.ml_chain is not None}")
            try:
                # 检查各个模型是否存在
                print(f"【调试】异常检测模型是否存在: {self.ml_chain.anomaly_model.model is not None}")
                print(f"【调试】攻击链模型是否存在: {self.ml_chain.attack_chain_model.model is not None}")
                print(f"【调试】IP信誉模型是否存在: {self.ml_chain.ip_reputation_model is not None}")
                
                enhanced_result = self.ml_chain.enhance_security_analysis(
                    sql_result=sql_result,
                    original_analysis=analysis_result
                )
                
                print(f"【调试】增强后的分析结果中是否包含ml_analysis: {'ml_analysis' in enhanced_result}")
                if 'ml_analysis' in enhanced_result:
                    print(f"【调试】ml_analysis内容: {enhanced_result['ml_analysis']}")
                    
                analysis_result = enhanced_result
            except Exception as e:
                logger.error(f"机器学习增强分析失败: {e}")
                print(f"【调试】机器学习增强分析失败: {e}")
                import traceback
                print(f"【调试】错误详情: {traceback.format_exc()}")
                # 添加错误信息但继续使用基础分析结果
                analysis_result["ml_error"] = str(e)
                
        # 确保关键发现和建议不超过3条
        analysis_result["key_findings"] = analysis_result["key_findings"][:3]
        analysis_result["recommendations"] = analysis_result["recommendations"][:3]
        
        # 生成详细分析
        detailed_analysis = f"安全风险等级: {analysis_result['risk_level']}\n\n"
        
        if analysis_result["key_findings"]:
            detailed_analysis += "关键发现:\n"
            for i, finding in enumerate(analysis_result["key_findings"]):
                detailed_analysis += f"{i+1}. {finding}\n"
                
        if analysis_result["recommendations"]:
            detailed_analysis += "\n安全建议:\n"
            for i, rec in enumerate(analysis_result["recommendations"]):
                detailed_analysis += f"{i+1}. {rec}\n"
                
        if "ip_analysis" in analysis_result:
            detailed_analysis += f"\nIP地址分析:\n{analysis_result['ip_analysis']}\n"
            
        if "ml_analysis" in analysis_result:
            detailed_analysis += f"\n机器学习分析:\n{analysis_result['ml_analysis']}\n"
            
        analysis_result["detailed_analysis"] = detailed_analysis
        
        return analysis_result
    
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
        if 'ip_analysis' in analysis and analysis['ip_analysis']:
            output += "### IP分析\n\n"
            output += f"{analysis['ip_analysis']}\n\n"
            
        # 添加IP关联性分析
        if 'ip_correlation' in analysis and analysis['ip_correlation']:
            output += "### IP关联性分析\n\n"
            output += f"{analysis['ip_correlation']}\n\n"
            
        # 添加机器学习分析
        if 'ml_analysis' in analysis and analysis['ml_analysis']:
            output += "### 机器学习分析\n\n"
            output += f"{analysis['ml_analysis']}\n\n"
            
        # 添加详情
        if 'details' in analysis and analysis['details']:
            output += "### 详情\n\n"
            output += f"{analysis['details']}\n\n"
            
        # 添加机器学习增强标记
        if analysis.get('ml_enhanced', False):
            output += "\n\n---\n*本分析已通过机器学习模型增强*"
            
        return output 