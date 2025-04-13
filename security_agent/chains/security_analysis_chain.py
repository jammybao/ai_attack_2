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
        """分析SQL查询结果中的IP地址
        
        Args:
            sql_result: SQL查询结果字符串
            
        Returns:
            IP地址分析结果
        """
        # 默认结果结构
        result = {
            "total_ips_found": 0,
            "unique_ips": set(),
            "internal_ips": [],  # [(ip, network_type), ...]
            "external_ips": [],  # [ip, ...]
            "frequent_ips": []   # [(ip, count), ...]
        }
        
        # 如果结果为空，直接返回
        if not sql_result or sql_result == "[]" or sql_result == "()":
            return result
            
        try:
            # 提取IP地址
            ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
            all_ips = re.findall(ip_pattern, sql_result)
            
            # 提取源IP和网络类型
            src_ip_pattern = r"'((?:\d{1,3}\.){3}\d{1,3})',\s+'(?:\d{1,3}\.){3}\d{1,3}'.*?'([^']*?(?:网络|网|内网|生产网)?)'.*?'(internal|external)'"
            src_ip_matches = re.findall(src_ip_pattern, sql_result)
            
            # 提取内部/外部IP信息
            for match in src_ip_matches:
                ip = match[0]
                network_type = match[1]
                ip_type = match[2]
                
                if ip not in result["unique_ips"]:
                    result["unique_ips"].add(ip)
                    
                if ip_type == "internal" or network_type:
                    # 检查是否已存在
                    if not any(internal_ip[0] == ip for internal_ip in result["internal_ips"]):
                        result["internal_ips"].append((ip, network_type))
                else:
                    if ip not in result["external_ips"]:
                        result["external_ips"].append(ip)
            
            # 处理未匹配到的IP
            for ip in all_ips:
                if ip not in result["unique_ips"]:
                    result["unique_ips"].add(ip)
                    
                    # 简单判断内外部IP
                    is_internal = False
                    
                    # 检查是否匹配典型内部IP模式
                    internal_patterns = [
                        r'^10\.',          # 10.0.0.0/8
                        r'^172\.(1[6-9]|2[0-9]|3[0-1])\.',  # 172.16.0.0/12
                        r'^192\.168\.'     # 192.168.0.0/16
                    ]
                    
                    for pattern in internal_patterns:
                        if re.match(pattern, ip):
                            is_internal = True
                            break
                            
                    if is_internal:
                        result["internal_ips"].append((ip, "未知"))
                    else:
                        result["external_ips"].append(ip)
            
            # 统计IP出现频率
            ip_counts = {}
            for ip in all_ips:
                if ip in ip_counts:
                    ip_counts[ip] += 1
                else:
                    ip_counts[ip] = 1
                    
            # 获取出现频率最高的IP（最多5个）
            sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)
            result["frequent_ips"] = sorted_ips[:5]
            
            # 更新总IP数量 - 只计算唯一IP，不重复计算
            result["total_ips_found"] = len(result["unique_ips"])
            
        except Exception as e:
            logger.error(f"分析IP地址时出错: {str(e)}")
            import traceback
            logger.error(traceback.format_exc())
            
        return result
        
    def _analyze_ip_by_network_type(self, ip: str, sql_result: str, internal_ips: List[tuple], external_ips: List[str]):
        """根据network_type分析IP是内部还是外部IP
        
        Args:
            ip: IP地址
            sql_result: SQL查询结果字符串
            internal_ips: 内部IP列表，会被修改
            external_ips: 外部IP列表，会被修改
        """
        # 尝试查找网络类型是否不为NULL且有意义
        network_type_pattern = r"'{}',.*?'([^']*网)'".format(re.escape(ip))
        network_type_match = re.search(network_type_pattern, sql_result)
        
        if network_type_match and network_type_match.group(1) and "网" in network_type_match.group(1):
            # 找到有效的network_type，说明是内部IP
            internal_ips.append((ip, network_type_match.group(1)))
            logger.info(f"从网络类型识别到内部IP: {ip}, network_type: {network_type_match.group(1)}")
        else:
            # 如果没有找到有效的network_type，视为外部IP
            external_ips.append(ip)
            logger.info(f"从网络类型识别到外部IP: {ip}")
    
    def analyze(self, question: str, sql_query: str, sql_result: str, use_ml: bool = True) -> Dict[str, Any]:
        """分析SQL查询结果并提供安全分析
        
        Args:
            question: 用户问题
            sql_query: 执行的SQL查询
            sql_result: SQL查询结果
            use_ml: 是否使用机器学习增强分析
            
        Returns:
            安全分析结果
        """
        # 分析IP地址信息
        ip_analysis = self._analyze_ip_addresses(sql_result)
        logger.info(f"IP分析结果: {ip_analysis}")
        
        # 提取事件相关信息
        event_analysis = self._analyze_events(sql_result)
        logger.info(f"事件分析结果: {event_analysis}")
        
        # 判断安全风险等级
        risk_level = self._evaluate_risk_level(ip_analysis, event_analysis)
        logger.info(f"风险等级评估: {risk_level}")
        
        # 生成关键发现和建议
        key_findings, recommendations = self._generate_findings_and_recommendations(
            ip_analysis, event_analysis, risk_level
        )
        
        # 构建基础安全分析结果
        security_analysis = {
            "risk_level": risk_level,
            "key_findings": key_findings,
            "recommendations": recommendations,
            "detailed_analysis": self._format_detailed_analysis(
                risk_level, key_findings, recommendations, ip_analysis, event_analysis
            ),
            "ip_analysis": self._format_ip_analysis(ip_analysis)
        }
        
        # 使用机器学习增强安全分析
        if use_ml:
            logger.info("使用机器学习增强安全分析")
            security_analysis = self._apply_ml_analysis(question, sql_query, sql_result, security_analysis)
        
        return security_analysis
    
    def _apply_ml_analysis(
        self, 
        question: str, 
        sql_query: str, 
        sql_result: str, 
        security_analysis: Dict[str, Any]
    ) -> Dict[str, Any]:
        """应用机器学习分析
        
        Args:
            question: 用户问题
            sql_query: SQL查询
            sql_result: SQL查询结果
            security_analysis: 基础安全分析结果
            
        Returns:
            增强后的安全分析结果
        """
        try:
            # 日志调试信息
            print("【调试】开始使用机器学习增强安全分析")
            print(f"【调试】ml_chain是否存在: {self.ml_chain is not None}")
            
            if not self.ml_chain:
                logger.warning("机器学习链未配置，跳过ML分析")
                return security_analysis
            
            # 使用ML链分析SQL结果
            ml_results = self.ml_chain.analyze(sql_result)
            
            # 检查是否有有效结果
            if not ml_results:
                logger.warning("机器学习分析返回空结果")
                return security_analysis
            
            # 检查是否存在异常
            anomalies = ml_results.get("anomalies", [])
            if anomalies:
                # 添加异常信息到安全分析
                if "key_findings" not in security_analysis:
                    security_analysis["key_findings"] = []
                
                anomaly_count = len([a for a in anomalies if a.get("is_anomaly", False)])
                if anomaly_count > 0:
                    security_analysis["key_findings"].append(
                        f"机器学习分析发现{anomaly_count}个异常行为模式"
                    )
            
            # 处理IP信誉分析结果
            ip_reputation = ml_results.get("ip_reputation", {})
            external_ips = ip_reputation.get("external_src_ips", []) + ip_reputation.get("external_dst_ips", [])
            
            if external_ips:
                # 更新external_ips列表
                unique_external_ips = set(ip for ip, _ in external_ips)
                
                # 更新IP分析信息
                if "ip_analysis" in security_analysis:
                    ip_analysis_text = security_analysis["ip_analysis"]
                    
                    # 如果还没有外部IP信息，添加它
                    if "外部IP:" not in ip_analysis_text and unique_external_ips:
                        ip_list_str = ", ".join(list(unique_external_ips)[:5])
                        if len(unique_external_ips) > 5:
                            ip_list_str += f"...等{len(unique_external_ips)}个"
                        
                        ip_analysis_text += f"\n\n外部IP: {ip_list_str}"
                        security_analysis["ip_analysis"] = ip_analysis_text
                
                # 添加或更新关键发现
                if "key_findings" in security_analysis:
                    # 移除现有的外部IP发现
                    security_analysis["key_findings"] = [
                        finding for finding in security_analysis["key_findings"]
                        if not (isinstance(finding, str) and "外部IP" in finding)
                    ]
                    
                    # 添加新的发现
                    if unique_external_ips:
                        security_analysis["key_findings"].append(
                            f"发现{len(unique_external_ips)}个外部IP，存在潜在安全风险"
                        )
            
            # 处理预测攻击结果
            predicted_attacks = ml_results.get("predicted_attacks", [])
            if predicted_attacks:
                # 添加预测攻击信息
                security_analysis["predicted_attacks"] = [
                    {
                        "target_ip": attack.get("target_ip", "未知"),
                        "attack_type": attack.get("attack_type", "未知"),
                        "probability": attack.get("probability", 0) * 100,  # 转为百分比
                        "timeframe": attack.get("timeframe", "未知")
                    }
                    for attack in predicted_attacks[:3]  # 最多取前3个预测
                ]
                
                # 添加预测攻击的关键发现
                if security_analysis.get("key_findings") and predicted_attacks:
                    security_analysis["key_findings"].append(
                        f"预测未来24小时内可能发生{len(predicted_attacks)}种攻击"
                    )
            
            # 如果ML分析显示风险更高，更新风险级别
            if (ip_reputation.get("high_risk_count", 0) > 3 or 
                any(attack.get("probability", 0) > 0.8 for attack in predicted_attacks)):
                # 提高风险等级
                if security_analysis["risk_level"] == "低":
                    security_analysis["risk_level"] = "中"
                elif security_analysis["risk_level"] == "中":
                    security_analysis["risk_level"] = "高"
            
            # 添加ML分析标记，表示已使用机器学习增强
            security_analysis["ml_enhanced"] = True
            
            return security_analysis
        except Exception as e:
            logger.error(f"应用机器学习分析时出错: {str(e)}")
            return security_analysis
    
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

    def _analyze_events(self, sql_result: str) -> Dict[str, Any]:
        """分析事件相关信息
        
        Args:
            sql_result: SQL查询结果
            
        Returns:
            事件分析结果
        """
        events = []
        high_risk_events = []
        event_types = set()
        
        # 提取事件信息
        try:
            # 计算元组数量 - 这是实际记录数
            tuple_count = sql_result.count("(datetime.datetime")
            logger.info(f"SQL结果包含 {tuple_count} 条记录")
            
            # 查找threat_level和signature
            threat_pattern = r"'([^']+)',\s+(\d+),\s+'([^']+)'"
            matches = re.findall(threat_pattern, sql_result)
            
            for match in matches:
                try:
                    if len(match) >= 3:
                        ip = match[0]
                        threat_level = int(match[1])
                        signature = match[2]
                        
                        event = {
                            "ip": ip,
                            "threat_level": threat_level,
                            "signature": signature
                        }
                        
                        events.append(event)
                        event_types.add(signature)
                        
                        if threat_level >= 30:
                            high_risk_events.append(event)
                except:
                    continue
                    
            # 匹配另一种模式
            alt_pattern = r"(\d+),\s+'([^']+)'"
            alt_matches = re.findall(alt_pattern, sql_result)
            
            for match in alt_matches:
                try:
                    if len(match) >= 2:
                        threat_level = int(match[0])
                        signature = match[1]
                        
                        # 查找附近的IP
                        ip_match = re.search(r"'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'.*?" + re.escape(match[1]), sql_result)
                        ip = ip_match.group(1) if ip_match else "未知"
                        
                        event = {
                            "ip": ip,
                            "threat_level": threat_level,
                            "signature": signature
                        }
                        
                        # 避免重复
                        if not any(e["ip"] == ip and e["signature"] == signature for e in events):
                            events.append(event)
                            event_types.add(signature)
                            
                            if threat_level >= 30:
                                high_risk_events.append(event)
                except:
                    continue
                    
            # 限制事件数量与元组数量一致
            if len(events) > tuple_count:
                logger.warning(f"提取的事件数量({len(events)})超过实际记录数({tuple_count})，将截断")
                events = events[:tuple_count]
                # 重新计算高风险事件
                high_risk_events = [e for e in events if e["threat_level"] >= 30]
        except Exception as e:
            logger.error(f"分析事件信息出错: {str(e)}")
        
        # 分类事件类型
        attack_patterns = {
            "SQL注入": ["sql", "injection", "注入"],
            "XSS攻击": ["xss", "cross site", "跨站"],
            "暴力破解": ["brute force", "bruteforce", "暴力", "字典攻击"],
            "端口扫描": ["scan", "扫描", "nmap"],
            "恶意文件": ["malware", "virus", "木马", "恶意软件"],
            "可疑行为": ["suspicious", "可疑", "异常", "download", "下载"],
            "权限提升": ["privilege", "escalation", "权限", "提升"],
            "信息泄露": ["information", "disclosure", "泄露", "泄漏"],
            "未知攻击": []  # 默认分类
        }
        
        categorized_events = {}
        for event in events:
            signature = event["signature"].lower() if isinstance(event["signature"], str) else ""
            category = "未知攻击"
            
            for cat, patterns in attack_patterns.items():
                if any(pattern in signature for pattern in patterns):
                    category = cat
                    break
            
            if category not in categorized_events:
                categorized_events[category] = []
            categorized_events[category].append(event)
        
        return {
            "total_events": len(events),
            "high_risk_events": high_risk_events,
            "event_types": list(event_types),
            "categorized_events": categorized_events
        }
    
    def _evaluate_risk_level(self, ip_analysis: Dict[str, Any], event_analysis: Dict[str, Any]) -> str:
        """评估安全风险等级
        
        Args:
            ip_analysis: IP分析结果
            event_analysis: 事件分析结果
            
        Returns:
            风险等级: 低, 中, 高
        """
        risk_level = "低"  # 默认风险等级
        
        # 外部IP是关键风险因素
        external_ip_count = len(ip_analysis["external_ips"])
        if external_ip_count > 0:
            logger.info(f"检测到 {external_ip_count} 个外部IP")
            if external_ip_count > 2:
                risk_level = "中"
            else:
                # 如果只有1-2个外部IP，根据事件类型判断
                has_dangerous_event = False
                for event in event_analysis["high_risk_events"]:
                    if "external" in event.get("ip_type", "").lower():
                        has_dangerous_event = True
                        break
                
                if has_dangerous_event:
                    risk_level = "中"
        
        # 高风险事件会增加风险，但内部IP的事件风险级别较低
        high_risk_count = len(event_analysis["high_risk_events"])
        if high_risk_count > 10 and external_ip_count > 0:
            risk_level = "高"
        elif high_risk_count > 20:
            risk_level = "中"
            
        # 特定攻击类型会增加风险
        dangerous_categories = ["SQL注入", "恶意文件", "权限提升"]
        has_dangerous_event = False
        for category in dangerous_categories:
            if category in event_analysis["categorized_events"]:
                events = event_analysis["categorized_events"][category]
                for event in events:
                    # 检查是否有外部IP的危险事件
                    ip = event.get("ip", "")
                    if ip in ip_analysis["external_ips"]:
                        has_dangerous_event = True
                        break
                
                if has_dangerous_event:
                    break
                
        if has_dangerous_event and external_ip_count > 0:
            if risk_level == "低":
                risk_level = "中"
            elif risk_level == "中":
                risk_level = "高"
                    
        # 记录风险评估结果
        logger.info(f"风险评估结果: 外部IP数量={external_ip_count}, 高风险事件数量={high_risk_count}, 最终风险等级={risk_level}")
        return risk_level
    
    def _generate_findings_and_recommendations(
        self, 
        ip_analysis: Dict[str, Any],
        event_analysis: Dict[str, Any],
        risk_level: str
    ) -> Tuple[List[str], List[str]]:
        """生成关键发现和建议
        
        Args:
            ip_analysis: IP分析结果
            event_analysis: 事件分析结果
            risk_level: 风险等级
            
        Returns:
            关键发现和建议列表
        """
        key_findings = []
        recommendations = []
        
        # 外部IP相关发现
        if ip_analysis["external_ips"]:
            external_ip_count = len(ip_analysis["external_ips"])
            key_findings.append(f"发现{external_ip_count}个外部IP，存在潜在安全风险")
            recommendations.append("立即审查外部IP通信记录，确认是否为授权通信或存在攻击行为")
            
        # 高风险事件相关发现
        if event_analysis["high_risk_events"]:
            high_risk_count = len(event_analysis["high_risk_events"])
            key_findings.append(f"发现{high_risk_count}个高风险安全事件，需要注意")
            
            # 根据事件类型提供具体建议
            event_categories = event_analysis["categorized_events"]
            
            if "SQL注入" in event_categories:
                sql_events = event_categories["SQL注入"]
                if sql_events:
                    key_findings.append(f"发现{len(sql_events)}次SQL注入攻击尝试")
                    recommendations.append("检查并加固Web应用的输入验证机制，防止SQL注入")
                    
            if "XSS攻击" in event_categories:
                xss_events = event_categories["XSS攻击"]
                if xss_events:
                    key_findings.append(f"发现{len(xss_events)}次XSS攻击尝试")
                    recommendations.append("加强Web应用的输入过滤，启用内容安全策略(CSP)防止XSS攻击")
                    
            if "暴力破解" in event_categories:
                brute_events = event_categories["暴力破解"]
                if brute_events:
                    key_findings.append(f"发现{len(brute_events)}次暴力破解尝试")
                    recommendations.append("实施账户锁定策略，启用双因素认证，增强密码复杂度要求")
                    
            if "恶意文件" in event_categories:
                malware_events = event_categories["恶意文件"]
                if malware_events:
                    key_findings.append(f"发现{len(malware_events)}个恶意文件或下载")
                    recommendations.append("运行深度扫描，隔离受感染主机，更新杀毒软件和防恶意软件解决方案")
                    
        # 根据风险等级添加一般性建议
        if risk_level == "高":
            if not recommendations:
                recommendations.append("立即调查高风险事件，限制受影响系统的网络访问")
                recommendations.append("通知安全团队，准备事件响应计划")
        elif risk_level == "中":
            if not recommendations:
                recommendations.append("密切监控系统活动，增加日志审计频率")
                recommendations.append("审查安全策略，确保最佳实践的执行")
        else:  # 低风险
            if not recommendations:
                recommendations.append("继续监控系统活动，保持安全策略的最新状态")
                
        # 限制数量
        key_findings = key_findings[:3]
        recommendations = recommendations[:3]
                
        return key_findings, recommendations
    
    def _format_detailed_analysis(
        self, 
        risk_level: str, 
        key_findings: List[str], 
        recommendations: List[str],
        ip_analysis: Dict[str, Any],
        event_analysis: Dict[str, Any]
    ) -> str:
        """格式化详细分析内容
        
        Args:
            risk_level: 风险等级
            key_findings: 关键发现
            recommendations: 安全建议
            ip_analysis: IP分析结果
            event_analysis: 事件分析结果
            
        Returns:
            格式化的详细分析文本
        """
        detailed_analysis = f"安全风险等级: {risk_level}\n\n"
        
        if key_findings:
            detailed_analysis += "关键发现:\n"
            for i, finding in enumerate(key_findings):
                detailed_analysis += f"{i+1}. {finding}\n"
                
        if recommendations:
            detailed_analysis += "\n安全建议:\n"
            for i, rec in enumerate(recommendations):
                detailed_analysis += f"{i+1}. {rec}\n"
                
        ip_text = self._format_ip_analysis(ip_analysis)
        if ip_text:
            detailed_analysis += f"\nIP地址分析:\n{ip_text}\n"
            
        return detailed_analysis
    
    def _format_ip_analysis(self, ip_analysis: Dict[str, Any]) -> str:
        """格式化IP分析结果
        
        Args:
            ip_analysis: IP分析结果
            
        Returns:
            格式化的IP分析文本
        """
        if ip_analysis["total_ips_found"] == 0:
            return ""
            
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
        
        return ip_text 