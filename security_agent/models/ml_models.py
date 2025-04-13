"""
机器学习模型定义 - 用于安全风险检测
"""
import logging
import pickle
import numpy as np
import pandas as pd
from typing import List, Dict, Any, Optional, Union
from pathlib import Path
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger(__name__)

class BaseMLModel:
    """机器学习模型基类"""
    
    def __init__(self, model_path: Optional[str] = None):
        """初始化基础模型
        
        Args:
            model_path: 预训练模型路径，如果提供则加载模型
        """
        self.model = None
        self.scaler = None
        
        if model_path:
            self.load_model(model_path)
            
    def load_model(self, model_path: str):
        """加载预训练模型
        
        Args:
            model_path: 模型文件路径
        """
        try:
            model_file = Path(model_path)
            if model_file.exists():
                with open(model_file, 'rb') as f:
                    model_data = pickle.load(f)
                    self.model = model_data.get('model')
                    self.scaler = model_data.get('scaler')
                logger.info(f"成功加载模型: {model_path}")
            else:
                logger.warning(f"模型文件不存在: {model_path}")
        except Exception as e:
            logger.error(f"加载模型失败: {e}")
            
    def save_model(self, model_path: str):
        """保存训练好的模型
        
        Args:
            model_path: 保存模型的路径
        """
        try:
            model_data = {
                'model': self.model,
                'scaler': self.scaler
            }
            with open(model_path, 'wb') as f:
                pickle.dump(model_data, f)
            logger.info(f"模型保存成功: {model_path}")
        except Exception as e:
            logger.error(f"保存模型失败: {e}")
            
class AnomalyDetectionModel(BaseMLModel):
    """异常检测模型 - 使用隔离森林算法检测异常流量"""
    
    def __init__(self, model_path: Optional[str] = None):
        """初始化异常检测模型
        
        Args:
            model_path: 预训练模型路径，如果提供则加载模型
        """
        super().__init__(model_path)
        
        if not self.model:
            # 创建默认模型
            self.model = IsolationForest(
                n_estimators=100, 
                contamination=0.1,
                random_state=42
            )
            self.scaler = StandardScaler()
            
    def train(self, data: pd.DataFrame, features: List[str]):
        """训练异常检测模型
        
        Args:
            data: 训练数据 DataFrame
            features: 用于训练的特征列表
        """
        try:
            # 提取特征
            X = data[features].values
            
            # 数据标准化
            X_scaled = self.scaler.fit_transform(X)
            
            # 训练模型
            self.model.fit(X_scaled)
            logger.info("异常检测模型训练完成")
        except Exception as e:
            logger.error(f"训练异常检测模型失败: {e}")
            
    def predict(self, data: pd.DataFrame, features: List[str]) -> np.ndarray:
        """预测数据点是否为异常
        
        Args:
            data: 需要预测的数据 DataFrame
            features: 用于预测的特征列表
            
        Returns:
            预测结果数组，1表示正常，-1表示异常
        """
        if self.model is None:
            logger.error("模型尚未训练或加载")
            return np.ones(len(data))  # 默认返回全部正常
            
        try:
            # 提取特征
            X = data[features].values
            
            # 数据标准化
            X_scaled = self.scaler.transform(X)
            
            # 预测
            predictions = self.model.predict(X_scaled)
            return predictions
        except Exception as e:
            logger.error(f"异常检测预测失败: {e}")
            return np.ones(len(data))  # 出错时默认返回全部正常
            
    def calculate_anomaly_score(self, data: pd.DataFrame, features: List[str]) -> np.ndarray:
        """计算异常分数
        
        Args:
            data: 需要计算异常分数的数据 DataFrame
            features: 用于计算的特征列表
            
        Returns:
            异常分数数组，分数越低表示越异常
        """
        if self.model is None:
            logger.error("模型尚未训练或加载")
            return np.zeros(len(data))
            
        try:
            # 提取特征
            X = data[features].values
            
            # 数据标准化
            X_scaled = self.scaler.transform(X)
            
            # 计算异常分数
            scores = self.model.decision_function(X_scaled)
            
            # 转换为 0-100 的标准化分数，分数越高表示越异常
            normalized_scores = 100 * (1 - (scores - scores.min()) / (scores.max() - scores.min() + 1e-10))
            return normalized_scores
        except Exception as e:
            logger.error(f"计算异常分数失败: {e}")
            return np.zeros(len(data))

    def detect_anomalies(self, data: pd.DataFrame, features: Optional[List[str]] = None) -> Dict[str, Any]:
        """检测数据中的异常并返回详细结果
        
        Args:
            data: 需要检测的数据 DataFrame
            features: 用于检测的特征列表，如果为None则使用所有数值列
            
        Returns:
            异常检测结果字典
        """
        if data.empty:
            logger.warning("输入数据为空，无法执行异常检测")
            return {
                "anomaly_found": False,
                "anomaly_count": 0,
                "anomaly_percentage": 0,
                "avg_anomaly_score": 0,
                "top_anomalies": [],
                "anomaly_samples": []
            }
            
        try:
            # 如果未指定特征，使用所有数值列
            if features is None:
                features = data.select_dtypes(include=['number']).columns.tolist()
                
            # 确保至少有一个特征
            if not features or not all(f in data.columns for f in features):
                logger.warning(f"未找到指定的特征列: {features}")
                features = ['threat_level'] if 'threat_level' in data.columns else data.select_dtypes(include=['number']).columns.tolist()[:1]
                
            # 如果没有可用特征，返回空结果
            if not features:
                logger.warning("没有可用特征进行异常检测")
                return {
                    "anomaly_found": False,
                    "anomaly_count": 0,
                    "anomaly_percentage": 0,
                    "avg_anomaly_score": 0,
                    "top_anomalies": [],
                    "anomaly_samples": []
                }
            
            # 确保模型存在
            if self.model is None:
                logger.info("创建新的异常检测模型")
                self.model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
                self.scaler = StandardScaler()
                
                # 拟合模型
                X = data[features].fillna(0).values
                self.scaler.fit(X)
                X_scaled = self.scaler.transform(X)
                self.model.fit(X_scaled)
            
            # 提取特征
            X = data[features].fillna(0).values
            
            # 数据标准化
            if self.scaler:
                X_scaled = self.scaler.transform(X)
            else:
                scaler = StandardScaler()
                X_scaled = scaler.fit_transform(X)
            
            # 预测异常
            predictions = self.model.predict(X_scaled)
            anomaly_scores = self.model.decision_function(X_scaled)
            
            # 计算异常指标
            anomalies = predictions == -1
            anomaly_count = np.sum(anomalies)
            anomaly_percentage = 100 * anomaly_count / len(data) if len(data) > 0 else 0
            avg_anomaly_score = np.mean(100 * (1 - (anomaly_scores - anomaly_scores.min()) / (anomaly_scores.max() - anomaly_scores.min() + 1e-10)))
            
            # 识别top异常
            top_anomalies = []
            if anomaly_count > 0:
                # 创建包含异常分数的数据副本
                anomaly_df = data.copy()
                anomaly_df['anomaly'] = anomalies
                anomaly_df['anomaly_score'] = 100 * (1 - (anomaly_scores - anomaly_scores.min()) / (anomaly_scores.max() - anomaly_scores.min() + 1e-10))
                
                # 选择异常记录并按分数排序
                anomaly_records = anomaly_df[anomaly_df['anomaly']].sort_values('anomaly_score', ascending=False)
                
                # 提取前5个异常
                for _, row in anomaly_records.head(5).iterrows():
                    anomaly = {}
                    # 添加IP地址（如果存在）
                    if 'src_ip' in row:
                        anomaly['ip'] = row['src_ip']
                    # 添加风险等级（如果存在）
                    if 'threat_level' in row:
                        anomaly['threat_level'] = row['threat_level']
                    anomaly['is_anomaly'] = True
                    top_anomalies.append(anomaly)
            
            # 识别异常样本描述
            anomaly_samples = []
            if anomaly_count > 0:
                if 'threat_level' in data.columns:
                    high_threat = data['threat_level'].max() if not data['threat_level'].empty else 0
                    if high_threat >= 50:
                        anomaly_samples.append("High threat level detected")
                
                if 'dst_ip' in data.columns and len(data['dst_ip'].unique()) < 3 and len(data) > 10:
                    anomaly_samples.append("Traffic concentrated to few destinations")
                
                if 'src_ip' in data.columns and 'ip_type' in data.columns:
                    external_ips = data[data['ip_type'] == 'external']
                    if len(external_ips) > 0.6 * len(data):
                        anomaly_samples.append("High external IP traffic")
            
            return {
                "anomaly_found": anomaly_count > 0,
                "anomaly_count": int(anomaly_count),
                "anomaly_percentage": float(anomaly_percentage),
                "avg_anomaly_score": float(avg_anomaly_score),
                "top_anomalies": top_anomalies,
                "anomaly_samples": anomaly_samples
            }
        except Exception as e:
            logger.error(f"检测异常失败: {str(e)}")
            import traceback
            logger.error(traceback.format_exc())
            
            return {
                "anomaly_found": False,
                "anomaly_count": 0,
                "anomaly_percentage": 0,
                "avg_anomaly_score": 0,
                "top_anomalies": [],
                "anomaly_samples": []
            }

class IPReputationModel(BaseMLModel):
    """IP信誉评分模型 - 评估IP地址的可信度"""
    
    def __init__(self, model_path: Optional[str] = None, ip_reputation_db: Optional[Dict[str, float]] = None):
        """初始化IP信誉评分模型
        
        Args:
            model_path: 预训练模型路径，如果提供则加载模型
            ip_reputation_db: IP信誉数据库，如果提供则使用该数据库
        """
        self.model = None
        self.scaler = None
        self.ip_reputation_db = ip_reputation_db or {}
        
        if model_path:
            self.load_model(model_path)
            
    def load_model(self, model_path: str):
        """加载预训练模型 - 重写基类方法适应IP信誉模型的特殊保存方式
        
        Args:
            model_path: 模型文件路径
        """
        try:
            model_file = Path(model_path)
            if model_file.exists():
                with open(model_file, 'rb') as f:
                    loaded_data = pickle.load(f)
                    # 检查是否是直接序列化的IPReputationModel对象
                    if isinstance(loaded_data, IPReputationModel):
                        self.ip_reputation_db = loaded_data.ip_reputation_db
                    # 检查是否是标准字典格式
                    elif isinstance(loaded_data, dict) and 'model' in loaded_data:
                        self.model = loaded_data.get('model')
                        self.scaler = loaded_data.get('scaler')
                        if 'ip_reputation_db' in loaded_data:
                            self.ip_reputation_db = loaded_data['ip_reputation_db']
                    # 检查是否直接是信誉数据库字典
                    elif isinstance(loaded_data, dict):
                        self.ip_reputation_db = loaded_data
                logger.info(f"成功加载IP信誉模型: {model_path}")
            else:
                logger.warning(f"模型文件不存在: {model_path}")
        except Exception as e:
            logger.error(f"加载IP信誉模型失败: {e}")
    
    def update_reputation(self, ip: str, score: float):
        """更新IP信誉分数
        
        Args:
            ip: IP地址
            score: 新的信誉分数
        """
        if ip in self.ip_reputation_db:
            # 使用指数加权平均更新分数
            alpha = 0.7  # 新分数的权重
            self.ip_reputation_db[ip] = alpha * score + (1 - alpha) * self.ip_reputation_db[ip]
        else:
            self.ip_reputation_db[ip] = score
            
    def get_reputation(self, ip: str) -> float:
        """获取IP地址的信誉分数
        
        Args:
            ip: IP地址
            
        Returns:
            信誉分数，0-100之间，分数越低表示越可疑
        """
        return self.ip_reputation_db.get(ip, 50.0)  # 默认中等信誉
        
    def batch_get_reputation(self, ips: List[str]) -> Dict[str, float]:
        """批量获取IP地址的信誉分数
        
        Args:
            ips: IP地址列表
            
        Returns:
            IP地址与信誉分数的映射字典
        """
        return {ip: self.get_reputation(ip) for ip in ips}

    def analyze_reputation(self, data: pd.DataFrame) -> Dict[str, Any]:
        """分析数据中IP的信誉状态
        
        Args:
            data: 包含IP信息的DataFrame
            
        Returns:
            IP信誉分析结果字典
        """
        if data.empty:
            logger.warning("输入数据为空，无法执行IP信誉分析")
            return {
                "suspicious_ips_found": False,
                "suspicious_src_ips": [],
                "suspicious_dst_ips": [],
                "internal_src_ips": [],
                "internal_dst_ips": [],
                "external_src_ips": [],
                "external_dst_ips": [],
                "ip_reputation_scores": {}
            }
        
        try:
            # 提取源IP和目的IP
            src_ips = []
            dst_ips = []
            
            if 'src_ip' in data.columns:
                src_ips = data['src_ip'].unique().tolist()
            
            if 'dst_ip' in data.columns:
                dst_ips = data['dst_ip'].unique().tolist()
            
            # 获取所有IP的信誉分数
            all_ips = set(src_ips + dst_ips)
            reputation_scores = self.batch_get_reputation(list(all_ips))
            
            # 识别可疑IP（分数低于30）
            suspicious_ips = [(ip, score) for ip, score in reputation_scores.items() if score < 30]
            suspicious_src_ips = [(ip, score) for ip, score in suspicious_ips if ip in src_ips]
            suspicious_dst_ips = [(ip, score) for ip, score in suspicious_ips if ip in dst_ips]
            
            # 区分内部和外部IP
            internal_src_ips = []
            external_src_ips = []
            internal_dst_ips = []
            external_dst_ips = []
            
            if 'ip_type' in data.columns and 'src_ip' in data.columns:
                for ip in src_ips:
                    ip_type = data[data['src_ip'] == ip]['ip_type'].iloc[0] if not data[data['src_ip'] == ip].empty else 'unknown'
                    network_type = data[data['src_ip'] == ip]['network_type'].iloc[0] if 'network_type' in data.columns and not data[data['src_ip'] == ip].empty else None
                    
                    if ip_type == 'internal':
                        internal_src_ips.append((ip, reputation_scores.get(ip, 50), [network_type] if network_type else []))
                    else:
                        external_src_ips.append((ip, reputation_scores.get(ip, 50)))
            
            if 'ip_type' in data.columns and 'dst_ip' in data.columns:
                for ip in dst_ips:
                    # 查找该IP是否作为源IP出现过，如果是则使用其ip_type
                    if ip in src_ips:
                        ip_data = data[data['src_ip'] == ip]
                        if not ip_data.empty:
                            ip_type = ip_data['ip_type'].iloc[0]
                            network_type = ip_data['network_type'].iloc[0] if 'network_type' in ip_data.columns else None
                        else:
                            ip_type = 'unknown'
                            network_type = None
                    else:
                        # 检查目标IP是否在所有IP中
                        ip_data = data[data['dst_ip'] == ip]
                        if not ip_data.empty and 'ip_type' in ip_data.columns:
                            ip_type = ip_data['ip_type'].iloc[0]
                            network_type = ip_data['network_type'].iloc[0] if 'network_type' in ip_data.columns else None
                        else:
                            # 如果目标IP不在我们的IP数据中，假定为外部IP
                            ip_type = 'external'
                            network_type = None
                    
                    if ip_type == 'internal':
                        internal_dst_ips.append((ip, reputation_scores.get(ip, 50), [network_type] if network_type else []))
                    else:
                        external_dst_ips.append((ip, reputation_scores.get(ip, 50)))
            
            # 统计高风险IP数量
            high_risk_count = len([ip for ip, score in reputation_scores.items() if score < 20])
            
            return {
                "suspicious_ips_found": len(suspicious_ips) > 0,
                "suspicious_src_ips": suspicious_src_ips,
                "suspicious_dst_ips": suspicious_dst_ips,
                "internal_src_ips": internal_src_ips,
                "internal_dst_ips": internal_dst_ips,
                "external_src_ips": external_src_ips,
                "external_dst_ips": external_dst_ips,
                "ip_reputation_scores": reputation_scores,
                "high_risk_count": high_risk_count
            }
        except Exception as e:
            logger.error(f"分析IP信誉失败: {str(e)}")
            import traceback
            logger.error(traceback.format_exc())
            
            return {
                "suspicious_ips_found": False,
                "suspicious_src_ips": [],
                "suspicious_dst_ips": [],
                "internal_src_ips": [],
                "internal_dst_ips": [],
                "external_src_ips": [],
                "external_dst_ips": [],
                "ip_reputation_scores": {},
                "high_risk_count": 0
            }

class AttackChainModel(BaseMLModel):
    """攻击链预测模型 - 预测攻击的下一步行为和攻击链路"""
    
    def __init__(self, model_path: Optional[str] = None):
        """初始化攻击链预测模型
        
        Args:
            model_path: 预训练模型路径，如果提供则加载模型
        """
        super().__init__(model_path)
        
        if not self.model:
            # 创建默认模型
            self.model = RandomForestClassifier(
                n_estimators=100, 
                max_depth=10,
                random_state=42
            )
            self.scaler = StandardScaler()
            
    def train(self, data: pd.DataFrame, features: List[str], target: str):
        """训练攻击链预测模型
        
        Args:
            data: 训练数据 DataFrame
            features: 用于训练的特征列表
            target: 目标变量字段名
        """
        try:
            # 提取特征和目标
            X = data[features].values
            y = data[target].values
            
            # 数据标准化
            X_scaled = self.scaler.fit_transform(X)
            
            # 训练模型
            self.model.fit(X_scaled, y)
            logger.info("攻击链预测模型训练完成")
        except Exception as e:
            logger.error(f"训练攻击链预测模型失败: {e}")
            
    def predict_next_step(self, data: pd.DataFrame, features: List[str]) -> np.ndarray:
        """预测攻击的下一步行为
        
        Args:
            data: 需要预测的数据 DataFrame
            features: 用于预测的特征列表
            
        Returns:
            预测的下一步攻击行为
        """
        if self.model is None:
            logger.error("模型尚未训练或加载")
            return np.array(["unknown"] * len(data))
            
        try:
            # 提取特征
            X = data[features].values
            
            # 数据标准化
            X_scaled = self.scaler.transform(X)
            
            # 预测
            predictions = self.model.predict(X_scaled)
            return predictions
        except Exception as e:
            logger.error(f"攻击链预测失败: {e}")
            return np.array(["unknown"] * len(data))
            
    def predict_attack_probability(self, data: pd.DataFrame, features: List[str]) -> Dict[str, np.ndarray]:
        """预测各种攻击类型的概率
        
        Args:
            data: 需要预测的数据 DataFrame
            features: 用于预测的特征列表
            
        Returns:
            各种攻击类型的概率字典
        """
        if self.model is None:
            logger.error("模型尚未训练或加载")
            return {}
            
        try:
            # 提取特征
            X = data[features].values
            
            # 数据标准化
            X_scaled = self.scaler.transform(X)
            
            # 预测概率
            proba = self.model.predict_proba(X_scaled)
            
            # 构建结果字典
            classes = self.model.classes_
            result = {}
            for i, class_name in enumerate(classes):
                result[class_name] = proba[:, i]
                
            return result
        except Exception as e:
            logger.error(f"攻击概率预测失败: {e}")
            return {}

    def predict_attacks(self, data: pd.DataFrame) -> Dict[str, Any]:
        """预测可能的攻击
        
        Args:
            data: 安全数据DataFrame
            
        Returns:
            攻击预测结果字典
        """
        if data.empty:
            logger.warning("输入数据为空，无法执行攻击预测")
            return {
                "attack_patterns_found": False,
                "attack_probabilities": [],
                "predicted_attacks": []
            }
        
        try:
            # 获取唯一的签名类型
            signatures = []
            if 'signature' in data.columns:
                signatures = data['signature'].unique().tolist()
            
            # 从签名中提取攻击类型
            attack_types = set()
            for sig in signatures:
                if isinstance(sig, str):
                    # 提取基本攻击类型
                    if 'sql' in sig.lower() and ('注入' in sig.lower() or 'injection' in sig.lower()):
                        attack_types.add("SQL注入")
                    elif 'xss' in sig.lower():
                        attack_types.add("XSS攻击")
                    elif 'scan' in sig.lower() or '扫描' in sig.lower():
                        attack_types.add("端口扫描")
                    elif 'brute' in sig.lower() or 'force' in sig.lower() or '暴力' in sig.lower():
                        attack_types.add("暴力破解")
                    elif 'malware' in sig.lower() or '恶意软件' in sig.lower() or 'virus' in sig.lower() or '病毒' in sig.lower():
                        attack_types.add("恶意软件")
            
            # 根据攻击类型生成攻击概率
            attack_probabilities = []
            for attack_type in attack_types:
                # 计算这种攻击类型的概率
                relevant_sigs = [sig for sig in signatures if attack_type.lower() in str(sig).lower()]
                probability = min(0.85, 0.3 + (len(relevant_sigs) / len(signatures)) * 0.7) if signatures else 0.3
                attack_probabilities.append((attack_type, probability))
            
            # 根据源IP和目标IP预测可能的攻击
            predicted_attacks = []
            
            # 提取频繁通信的IP对
            ip_pairs = {}
            if 'src_ip' in data.columns and 'dst_ip' in data.columns:
                for _, row in data.iterrows():
                    src = row['src_ip']
                    dst = row['dst_ip']
                    pair = (src, dst)
                    ip_pairs[pair] = ip_pairs.get(pair, 0) + 1
            
            # 按频率排序IP对
            sorted_pairs = sorted(ip_pairs.items(), key=lambda x: x[1], reverse=True)
            
            # 生成预测攻击
            for attack_type, probability in attack_probabilities:
                # 为每种攻击类型预测一次攻击
                if sorted_pairs:
                    # 选择最频繁的IP对
                    (src_ip, dst_ip), _ = sorted_pairs[0]
                    
                    # 创建预测攻击
                    predicted_attack = {
                        "target_ip": dst_ip,
                        "attack_type": attack_type,
                        "probability": int(probability * 100),
                        "timeframe": "24小时内"
                    }
                    
                    predicted_attacks.append(predicted_attack)
                    
                    # 移除已使用的IP对
                    if len(sorted_pairs) > 1:
                        sorted_pairs = sorted_pairs[1:]
            
            return {
                "attack_patterns_found": len(attack_probabilities) > 0,
                "attack_probabilities": attack_probabilities,
                "predicted_attacks": predicted_attacks
            }
        except Exception as e:
            logger.error(f"预测攻击失败: {str(e)}")
            import traceback
            logger.error(traceback.format_exc())
            
            return {
                "attack_patterns_found": False,
                "attack_probabilities": [],
                "predicted_attacks": []
            } 