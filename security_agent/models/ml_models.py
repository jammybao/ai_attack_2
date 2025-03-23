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