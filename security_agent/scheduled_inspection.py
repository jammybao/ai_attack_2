"""
定时安全巡检模块

这个模块专门用于定时执行网络安全巡检，直接分析一小时内的安全数据，
无需复杂的SQL生成逻辑，专注于分析结果和预测可能的攻击。
"""
import os
import sys
import json
import time
import logging
import pymysql
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
from dotenv import load_dotenv

# 加载环境变量
load_dotenv()

# 导入机器学习模型
from security_agent.models.ml_models import (
    AnomalyDetectionModel, 
    IPReputationModel,
    AttackChainModel
)

# 设置日志
logger = logging.getLogger("scheduled_inspection")

class DirectSecurityInspection:
    """直接安全巡检类，专注于分析已有数据而非SQL生成"""
    
    def __init__(
        self,
        db_host: str = os.getenv("DB_HOST", "localhost"),
        db_user: str = os.getenv("DB_USER", "root"),
        db_password: str = os.getenv("DB_PASSWORD", "password"),
        db_name: str = os.getenv("DB_NAME", "itm"),
        db_port: int = int(os.getenv("DB_PORT", "3306")),
        reports_dir: str = "security_reports",
        anomaly_model_path: Optional[str] = None,
        ip_reputation_model_path: Optional[str] = None,
        attack_chain_model_path: Optional[str] = None
    ):
        """初始化直接安全巡检
        
        Args:
            db_host: 数据库主机地址
            db_user: 数据库用户名
            db_password: 数据库密码
            db_name: 数据库名称
            db_port: 数据库端口
            reports_dir: 安全报告保存目录
            anomaly_model_path: 异常检测模型路径
            ip_reputation_model_path: IP信誉模型路径
            attack_chain_model_path: 攻击链预测模型路径
        """
        self.db_host = db_host
        self.db_user = db_user
        self.db_password = db_password
        self.db_name = db_name
        self.db_port = db_port
        self.reports_dir = reports_dir
        
        # 确保报告目录存在
        Path(reports_dir).mkdir(exist_ok=True)
        
        # 初始化模型
        self.anomaly_model = AnomalyDetectionModel(model_path=anomaly_model_path)
        self.ip_reputation_model = IPReputationModel(model_path=ip_reputation_model_path)
        self.attack_chain_model = AttackChainModel(model_path=attack_chain_model_path)
        
        # 缓存最近一次的巡检结果
        self.last_inspection_result = None
        self.last_inspection_time = None
        
        logger.info("直接安全巡检模块已初始化")
    
    def _connect_to_database(self):
        """连接到MySQL数据库
        
        Returns:
            数据库连接
        """
        try:
            connection = pymysql.connect(
                host=self.db_host,
                user=self.db_user,
                password=self.db_password,
                database=self.db_name,
                port=self.db_port,
                cursorclass=pymysql.cursors.DictCursor
            )
            return connection
        except Exception as e:
            logger.error(f"数据库连接失败: {str(e)}")
            return None
    
    def get_hourly_data(self, hours: int = 1) -> pd.DataFrame:
        """直接获取最近N小时的安全数据
        
        Args:
            hours: 获取最近多少小时的数据，默认1小时
            
        Returns:
            包含安全数据的DataFrame
        """
        try:
            # 连接数据库
            connection = self._connect_to_database()
            if not connection:
                logger.error("无法连接到数据库")
                return pd.DataFrame()
            
            try:
                with connection.cursor() as cursor:
                    # 获取最近N小时的数据
                    end_time = datetime.now()
                    start_time = end_time - timedelta(hours=hours)
                    
                    # 直接查询ids_ai表获取所有必要数据
                    query = """
                    SELECT 
                        ids_ai.event_time, 
                        ids_ai.src_ip, 
                        ids_ai.dst_ip, 
                        ids_ai.threat_level, 
                        ids_ai.signature,
                        ip_address.network_type,
                        CASE WHEN ip_address.network_type IS NULL THEN 'external' ELSE 'internal' END AS ip_type
                    FROM 
                        ids_ai
                    LEFT JOIN 
                        ip_address ON ids_ai.src_ip = ip_address.ip
                    WHERE 
                        ids_ai.event_time >= %s
                    ORDER BY 
                        ids_ai.event_time DESC
                    """
                    
                    # 执行查询
                    cursor.execute(query, (start_time,))
                    
                    # 获取结果
                    results = cursor.fetchall()
                    
                    # 创建DataFrame
                    df = pd.DataFrame(results)
                    
                    logger.info(f"成功获取最近{hours}小时的安全数据，共{len(df)}条记录")
                    return df
            finally:
                connection.close()
                
        except Exception as e:
            logger.error(f"获取安全数据时出错: {str(e)}")
            
            # 如果数据库操作失败，返回空DataFrame
            return pd.DataFrame()
    
    def analyze_security_data(self, data: pd.DataFrame) -> Dict[str, Any]:
        """分析安全数据
        
        Args:
            data: 安全数据DataFrame
            
        Returns:
            分析结果字典
        """
        # 如果数据为空，返回空结果
        if data.empty:
            logger.warning("没有安全数据可供分析")
            return {
                "risk_level": "未知",
                "smart_score": 100,  # 修改为100分，表示没有发现风险
                "external_attack_count": 0,
                "high_risk_events": [],
                "key_findings": ["没有安全数据可供分析"],
                "recommendations": ["检查数据收集系统是否正常工作"],
                "predicted_attacks": []
            }
        
        # 1. 基本统计分析
        total_events = len(data)
        high_risk_events_df = data[data['threat_level'] >= 30]
        high_risk_count = len(high_risk_events_df)
        external_ips = data[data['ip_type'] == 'external']
        external_attack_count = len(external_ips)
        
        # 2. 分析高风险事件
        high_risk_events = []
        for _, row in high_risk_events_df.iterrows():
            event = {
                "ip": row['src_ip'],
                "risk_level": "高" if row['threat_level'] >= 30 else "中",
                "event_type": self._classify_event_type(row['signature']),
                "description": row['signature']
            }
            high_risk_events.append(event)
        
        # 3. 使用异常检测模型找出异常行为
        try:
            numerical_features = ['threat_level']
            anomalies = self.anomaly_model.detect_anomalies(data, numerical_features)
            if anomalies.get("anomaly_found", False):
                # 将检测到的异常添加到高风险事件
                for anomaly in anomalies.get("top_anomalies", []):
                    if anomaly not in high_risk_events:
                        high_risk_events.append(anomaly)
        except Exception as e:
            logger.error(f"异常检测失败: {str(e)}")
        
        # 4. 分析IP信誉
        try:
            ip_reputation = self.ip_reputation_model.analyze_reputation(data)
            # 将高风险IP添加到高风险事件
            for ip, score in ip_reputation.get("suspicious_src_ips", []):
                if score > 0.7 and not any(event['ip'] == ip for event in high_risk_events):
                    high_risk_events.append({
                        "ip": ip,
                        "risk_level": "高",
                        "event_type": "可疑IP",
                        "description": f"IP信誉分数: {score:.2f}"
                    })
        except Exception as e:
            logger.error(f"IP信誉分析失败: {str(e)}")
        
        # 5. 预测可能的攻击
        predicted_attacks = []
        try:
            attack_predictions = self.attack_chain_model.predict_attacks(data)
            predicted_attacks = attack_predictions.get("predicted_attacks", [])
        except Exception as e:
            logger.error(f"攻击预测失败: {str(e)}")
        
        # 6. 生成关键发现和建议
        key_findings = self._generate_key_findings(data, high_risk_events)
        recommendations = self._generate_recommendations(high_risk_events, predicted_attacks)
        
        # 7. 计算整体风险等级和智能评分
        risk_level = self._calculate_risk_level(data, high_risk_events, external_attack_count)
        smart_score = self._calculate_smart_score(data, high_risk_events, predicted_attacks)
        
        # 整合结果
        result = {
            "risk_level": risk_level,
            "smart_score": smart_score,
            "external_attack_count": external_attack_count,
            "high_risk_events": high_risk_events,
            "key_findings": key_findings,
            "recommendations": recommendations,
            "predicted_attacks": predicted_attacks
        }
        
        return result
    
    def _classify_event_type(self, signature: str) -> str:
        """根据签名分类事件类型
        
        Args:
            signature: 事件签名
            
        Returns:
            事件类型
        """
        signature = str(signature).lower()
        
        if 'sql' in signature and ('注入' in signature or 'injection' in signature):
            return "SQL注入"
        elif 'xss' in signature:
            return "XSS攻击"
        elif 'scan' in signature or '扫描' in signature:
            return "端口扫描"
        elif 'brute' in signature or 'force' in signature or '暴力' in signature:
            return "暴力破解"
        elif 'malware' in signature or '恶意软件' in signature or 'virus' in signature or '病毒' in signature:
            return "恶意软件"
        elif 'rdp' in signature or '远程桌面' in signature:
            return "远程访问"
        elif 'sensitive' in signature or '敏感' in signature or 'data' in signature:
            return "敏感信息"
        else:
            return "可疑行为"
    
    def _generate_key_findings(self, data: pd.DataFrame, high_risk_events: List[Dict]) -> List[str]:
        """生成关键发现
        
        Args:
            data: 安全数据
            high_risk_events: 高风险事件列表
            
        Returns:
            关键发现列表
        """
        findings = []
        
        # 添加高风险事件总数
        if high_risk_events:
            findings.append(f"发现{len(high_risk_events)}个高风险安全事件，需要注意")
        
        # 统计各类攻击类型
        event_types = {}
        for event in high_risk_events:
            event_type = event.get("event_type", "未知")
            event_types[event_type] = event_types.get(event_type, 0) + 1
        
        # 添加攻击类型统计
        for event_type, count in event_types.items():
            if count > 0:
                findings.append(f"发现{count}次{event_type}尝试")
        
        # 添加外部IP分析
        external_ips = data[data['ip_type'] == 'external']
        if not external_ips.empty:
            findings.append(f"发现{len(external_ips)}次来自外部IP的连接")
        
        return findings
    
    def _generate_recommendations(self, high_risk_events: List[Dict], predicted_attacks: List[Dict]) -> List[str]:
        """生成安全建议
        
        Args:
            high_risk_events: 高风险事件列表
            predicted_attacks: 预测攻击列表
            
        Returns:
            安全建议列表
        """
        recommendations = []
        
        # 根据高风险事件类型生成建议
        event_types = set([event.get("event_type", "") for event in high_risk_events])
        
        if "SQL注入" in event_types:
            recommendations.append("检查并加固Web应用的输入验证机制，防止SQL注入")
        
        if "XSS攻击" in event_types:
            recommendations.append("加强Web应用的输入过滤，启用内容安全策略(CSP)防止XSS攻击")
        
        if "端口扫描" in event_types:
            recommendations.append("检查防火墙规则，仅开放必要端口，考虑启用入侵防御系统")
        
        if "暴力破解" in event_types:
            recommendations.append("实施账户锁定策略，考虑使用双因素认证增强安全性")
        
        if "远程访问" in event_types:
            recommendations.append("限制远程访问IP，使用VPN并确保RDP使用高强度加密")
        
        if "恶意软件" in event_types:
            recommendations.append("更新反病毒软件，对可疑系统进行全面扫描")
        
        # 根据预测攻击添加预防建议
        if predicted_attacks:
            recommendations.append("根据预测攻击模式，加强相关系统的监控和防护")
        
        # 如果没有特定建议，添加通用建议
        if not recommendations:
            recommendations.append("定期更新系统补丁，加强安全意识培训")
        
        return recommendations
    
    def _calculate_risk_level(self, data: pd.DataFrame, high_risk_events: List[Dict], external_attack_count: int) -> str:
        """计算整体风险等级
        
        Args:
            data: 安全数据
            high_risk_events: 高风险事件列表
            external_attack_count: 外部攻击次数
            
        Returns:
            风险等级: "高"、"中"、"低"
        """
        # 如果没有数据，返回未知
        if data.empty:
            return "未知"
        
        # 风险评分因素
        factors = []
        
        # 1. 高风险事件数量
        high_risk_ratio = len(high_risk_events) / len(data) if len(data) > 0 else 0
        if high_risk_ratio >= 0.3:
            factors.append(3)  # 高风险
        elif high_risk_ratio >= 0.1:
            factors.append(2)  # 中风险
        else:
            factors.append(1)  # 低风险
        
        # 2. 外部攻击比例
        external_ratio = external_attack_count / len(data) if len(data) > 0 else 0
        if external_ratio >= 0.2:
            factors.append(3)  # 高风险
        elif external_ratio >= 0.05:
            factors.append(2)  # 中风险
        else:
            factors.append(1)  # 低风险
        
        # 3. 最高威胁等级
        max_threat = data['threat_level'].max() if 'threat_level' in data.columns and not data.empty else 0
        if max_threat >= 50:
            factors.append(3)  # 高风险
        elif max_threat >= 30:
            factors.append(2)  # 中风险
        else:
            factors.append(1)  # 低风险
        
        # 4. 特定高风险事件类型
        critical_events = ["SQL注入", "XSS攻击", "恶意软件"]
        has_critical = any(event.get("event_type", "") in critical_events for event in high_risk_events)
        if has_critical:
            factors.append(3)  # 高风险
        
        # 计算平均风险分数
        avg_score = sum(factors) / len(factors) if factors else 1
        
        # 确定风险等级
        if avg_score >= 2.5:
            return "高"
        elif avg_score >= 1.5:
            return "中"
        else:
            return "低"
    
    def _calculate_smart_score(self, data: pd.DataFrame, high_risk_events: List[Dict], predicted_attacks: List[Dict]) -> int:
        """计算智能安全评分(0-100)，越高越安全
        
        Args:
            data: 安全数据
            high_risk_events: 高风险事件列表
            predicted_attacks: 预测攻击列表
            
        Returns:
            智能安全评分(0-100)
        """
        # 基础分数
        base_score = 100
        
        # 扣分项
        deductions = []
        
        # 1. 高风险事件扣分（降低单个事件的扣分权重）
        high_risk_deduction = min(40, len(high_risk_events) * 3)  # 从5降低到3
        deductions.append(high_risk_deduction)
        
        # 2. 外部攻击扣分（降低单个攻击的扣分权重）
        external_ips = data[data['ip_type'] == 'external']
        external_deduction = min(30, len(external_ips) * 2)  # 从3降低到2
        deductions.append(external_deduction)
        
        # 3. 预测攻击扣分
        prediction_deduction = min(20, len(predicted_attacks) * 5)  # 从7降低到5
        deductions.append(prediction_deduction)
        
        # 4. 根据最高威胁等级扣分
        max_threat = data['threat_level'].max() if 'threat_level' in data.columns and not data.empty else 0
        threat_deduction = min(30, int(max_threat * 0.5))  # 从0.6降低到0.5
        deductions.append(threat_deduction)
        
        # 计算最终分数，确保至少有1分（完全不为0）
        final_score = max(1, base_score - sum(deductions))
        
        return final_score
    
    def run_inspection(self, hours: int = 1) -> Dict[str, Any]:
        """执行定时安全巡检
        
        Args:
            hours: 分析最近多少小时的数据，默认1小时
            
        Returns:
            巡检结果字典
        """
        logger.info(f"开始执行最近{hours}小时的安全巡检")
        
        # 获取安全数据
        data = self.get_hourly_data(hours)
        
        # 分析数据
        result = self.analyze_security_data(data)
        
        # 保存结果
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{self.reports_dir}/direct_security_report_{timestamp}.json"
        
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
            
        logger.info(f"安全巡检报告已保存至 {filename}")
        
        # 缓存结果
        self.last_inspection_result = result
        self.last_inspection_time = datetime.now()
        
        return result
    
    def format_inspection_result(self, result: Dict[str, Any]) -> str:
        """格式化巡检结果
        
        Args:
            result: 巡检结果字典
            
        Returns:
            格式化的巡检结果
        """
        formatted = "## 安全风险评估\n\n"
        formatted += f"**风险等级**: {result.get('risk_level', '未知')}\n\n"
        formatted += f"**智能安全评分**: {result.get('smart_score', 0)}\n\n"
        
        # 关键发现
        if result.get('key_findings'):
            formatted += "### 关键发现\n\n"
            for i, finding in enumerate(result['key_findings'], 1):
                formatted += f"{i}. {finding}\n"
            formatted += "\n"
        
        # 安全建议
        if result.get('recommendations'):
            formatted += "### 安全建议\n\n"
            for i, recommendation in enumerate(result['recommendations'], 1):
                formatted += f"{i}. {recommendation}\n"
            formatted += "\n"
        
        # 高风险事件
        high_risk_events = result.get('high_risk_events', [])
        if high_risk_events:
            formatted += "### 高风险事件\n\n"
            formatted += "| IP地址 | 风险等级 | 事件类型 | 描述 |\n"
            formatted += "| ------ | -------- | -------- | ---- |\n"
            
            for event in high_risk_events[:10]:  # 最多显示10个
                formatted += f"| {event.get('ip', '未知')} | {event.get('risk_level', '未知')} | "
                formatted += f"{event.get('event_type', '未知')} | {event.get('description', '未知')} |\n"
                
            if len(high_risk_events) > 10:
                formatted += f"\n*还有 {len(high_risk_events) - 10} 个高风险事件未显示*\n"
            
            formatted += "\n"
        
        # 预测攻击
        predicted_attacks = result.get('predicted_attacks', [])
        if predicted_attacks:
            formatted += "### 预测攻击\n\n"
            formatted += "| 目标IP | 攻击类型 | 概率 | 时间框架 |\n"
            formatted += "| ------ | -------- | ---- | -------- |\n"
            
            for attack in predicted_attacks:
                formatted += f"| {attack.get('target_ip', '未知')} | {attack.get('attack_type', '未知')} | "
                formatted += f"{attack.get('probability', 0)}% | {attack.get('timeframe', '未知')} |\n"
                
            formatted += "\n"
        
        return formatted

# 用于测试的简单主函数
def main():
    """主函数，用于测试"""
    # 创建直接安全巡检实例
    inspector = DirectSecurityInspection()
    
    # 执行巡检
    result = inspector.run_inspection(hours=1)
    
    # 格式化并打印结果
    formatted = inspector.format_inspection_result(result)
    print(formatted)

if __name__ == "__main__":
    # 配置日志
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler("direct_inspection.log"),
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    main() 