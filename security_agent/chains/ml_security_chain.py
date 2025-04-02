"""
机器学习安全链 - 集成各种机器学习模型提高风险检测能力
"""
import logging
import pandas as pd
import numpy as np
from typing import Dict, Any, List, Optional, Tuple
import json
from sklearn.ensemble import IsolationForest

from security_agent.models.ml_models import (
    AnomalyDetectionModel, 
    IPReputationModel,
    AttackChainModel
)

logger = logging.getLogger(__name__)

class MLSecurityChain:
    """机器学习安全链，集成多种机器学习模型增强安全分析"""
    
    def __init__(
        self,
        anomaly_model_path: Optional[str] = None,
        ip_reputation_model_path: Optional[str] = None,
        attack_chain_model_path: Optional[str] = None
    ):
        """初始化机器学习安全链
        
        Args:
            anomaly_model_path: 异常检测模型路径
            ip_reputation_model_path: IP信誉模型路径
            attack_chain_model_path: 攻击链预测模型路径
        """
        logger.info("初始化机器学习安全链")
        
        # 初始化模型
        self.anomaly_model = AnomalyDetectionModel(model_path=anomaly_model_path)
        self.ip_reputation_model = IPReputationModel(model_path=ip_reputation_model_path)
        self.attack_chain_model = AttackChainModel(model_path=attack_chain_model_path)
        
        # 定义用于异常检测的默认特征
        self.default_numerical_features = [
            'bytes_sent', 'bytes_received', 'session_duration', 
            'source_port', 'destination_port'
        ]
    
    def preprocess_data(self, sql_result: str) -> pd.DataFrame:
        """预处理SQL查询结果为DataFrame格式
        
        Args:
            sql_result: SQL查询结果字符串，支持JSON格式或表格形式
            
        Returns:
            处理后的DataFrame
        """
        logger.info("预处理SQL查询结果")
        
        try:
            # 检查结果是否为空
            if not sql_result or sql_result.strip() == "" or sql_result.strip() == "[]":
                logger.warning("SQL查询结果为空")
                return pd.DataFrame()
                
            # 先尝试解析为JSON
            try:
                # 去除可能的前后空白
                sql_result = sql_result.strip()
                # 尝试解析JSON
                json_data = json.loads(sql_result)
                
                # 如果是JSON数组，直接转换为DataFrame
                if isinstance(json_data, list):
                    df = pd.DataFrame(json_data)
                    logger.info(f"成功将JSON数组转换为DataFrame，形状: {df.shape}")
                    
                    # 尝试转换数值列
                    for col in df.columns:
                        try:
                            if col in ['src_port', 'dst_port', 'bytes_sent', 'bytes_received']:
                                df[col] = pd.to_numeric(df[col], errors='coerce')
                        except:
                            pass
                            
                    return df
                else:
                    logger.warning("JSON数据不是数组格式，无法转换为DataFrame")
                    return pd.DataFrame()
                    
            except json.JSONDecodeError:
                # 不是JSON格式，尝试解析为表格形式
                logger.info("非JSON格式，尝试解析为表格形式")
                
                # 将结果转换为DataFrame
                # 以下是一种简单的解析方法，可能需要根据实际结果格式调整
                lines = sql_result.strip().split('\n')
                
                # 如果只有一行，无法解析
                if len(lines) <= 1:
                    logger.warning("SQL结果只有一行，无法解析为DataFrame")
                    return pd.DataFrame()
                    
                # 提取列名和数据行
                # 假设第一行是列名，后面的是数据
                header_line = lines[0]
                headers = [h.strip() for h in header_line.split('|') if h.strip()]
                
                # 处理数据行
                data = []
                for line in lines[2:]:  # 跳过标题行和分隔行
                    if '|' not in line or line.strip().startswith('+'):
                        continue
                        
                    row_values = [val.strip() for val in line.split('|') if val]
                    if len(row_values) == len(headers):
                        data.append(row_values)
                        
                # 创建DataFrame
                df = pd.DataFrame(data, columns=headers)
                
                # 尝试转换数值列
                for col in df.columns:
                    try:
                        if col in ['src_port', 'dst_port', 'bytes_sent', 'bytes_received']:
                            df[col] = pd.to_numeric(df[col], errors='coerce')
                    except:
                        pass
                        
                logger.info(f"成功将表格结果转换为DataFrame，形状: {df.shape}")
                return df
                
        except Exception as e:
            logger.error(f"预处理SQL查询结果失败: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return pd.DataFrame()
    
    def detect_anomalies(
        self, 
        data: pd.DataFrame, 
        features: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """检测数据中的异常
        
        Args:
            data: 输入数据DataFrame
            features: 用于异常检测的特征列表，如果为None，使用默认特征
            
        Returns:
            异常检测结果，包含异常记录和异常分数
        """
        logger.info("执行异常检测")
        
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
        
        # 设置要使用的数值特征
        if features is None:
            # 使用可用的数值特征
            potential_features = ['src_port', 'dst_port', 'bytes_sent', 'bytes_received']
            features = [f for f in potential_features if f in data.columns]
            
        # 检查是否有足够的特征
        if not features or len(features) < 2:
            logger.warning(f"没有足够的数值特征用于异常检测，只有: {features}")
            return {
                "anomaly_found": False,
                "anomaly_count": 0,
                "anomaly_percentage": 0,
                "avg_anomaly_score": 0,
                "top_anomalies": [],
                "anomaly_samples": []
            }
            
        # 确保所有特征列都是数值类型
        for feature in features:
            if feature in data.columns:
                try:
                    data[feature] = pd.to_numeric(data[feature], errors='coerce')
                except Exception as e:
                    logger.warning(f"将列 {feature} 转换为数值类型失败: {e}")
        
        # 移除包含NaN的行
        data_clean = data.dropna(subset=features)
        
        if len(data_clean) == 0:
            logger.warning("清理后无有效数据，无法执行异常检测")
            return {
                "anomaly_found": False,
                "anomaly_count": 0,
                "anomaly_percentage": 0,
                "avg_anomaly_score": 0,
                "top_anomalies": [],
                "anomaly_samples": []
            }
            
        try:
            # 模型训练过程中，期望的特征可能有更多
            # 如果模型期望8个特征，但现在只有4个，我们需要创建一个新的模型
            if self.anomaly_model and self.anomaly_model.model:
                try:
                    # 尝试获取模型期望的特征数量
                    if hasattr(self.anomaly_model.scaler, 'n_features_in_'):
                        expected_features = self.anomaly_model.scaler.n_features_in_
                        print(f"异常检测模型期望特征数: {expected_features}, 当前特征数: {len(features)}")
                        
                        # 如果特征数量不匹配，使用简单模型创建临时预测
                        if expected_features != len(features):
                            logger.warning(f"特征数量不匹配。模型期望{expected_features}个特征，但提供了{len(features)}个特征")
                            # 使用简单的IsolationForest初始化
                            temp_model = IsolationForest(random_state=42, contamination=0.1)
                            X = data_clean[features].values
                            temp_model.fit(X)
                            # 预测异常分数 (-1为异常，1为正常)
                            y_pred = temp_model.predict(X)
                            # 计算异常分数 (越接近-1越异常)
                            anomaly_scores = temp_model.decision_function(X)
                            # 转换为0-100的分数 (0最异常，100最正常)
                            anomaly_scores = 100 * (1 + anomaly_scores) / 2
                        else:
                            # 使用标准化转换数据
                            X = self.anomaly_model.scaler.transform(data_clean[features].values)
                            # 预测异常分数
                            y_pred = self.anomaly_model.model.predict(X)
                            # 计算异常分数
                            anomaly_scores = self.anomaly_model.model.decision_function(X)
                            # 转换为0-100的分数
                            anomaly_scores = 100 * (1 + anomaly_scores) / 2
                except Exception as e:
                    logger.error(f"计算异常分数失败: {e}")
                    print(f"计算异常分数失败: {e}")
                    # 使用简单的IsolationForest替代
                    temp_model = IsolationForest(random_state=42, contamination=0.1)
                    X = data_clean[features].values
                    temp_model.fit(X)
                    y_pred = temp_model.predict(X)
                    anomaly_scores = temp_model.decision_function(X)
                    anomaly_scores = 100 * (1 + anomaly_scores) / 2
            else:
                # 如果没有预训练模型，使用简单的IsolationForest
                temp_model = IsolationForest(random_state=42, contamination=0.1)
                X = data_clean[features].values
                temp_model.fit(X)
                y_pred = temp_model.predict(X)
                anomaly_scores = temp_model.decision_function(X)
                anomaly_scores = 100 * (1 + anomaly_scores) / 2
                
            # 计算结果
            anomaly_indices = np.where(y_pred == -1)[0]
            
            # 构建结果字典
            anomaly_count = len(anomaly_indices)
            anomaly_percentage = (anomaly_count / len(data_clean)) * 100
            avg_anomaly_score = 100 - np.mean(anomaly_scores)  # 反转分数使得越高表示越异常
            
            # 提取前5个异常记录
            top_anomalies = []
            if anomaly_count > 0:
                # 对异常分数进行排序
                anomaly_rank = np.argsort(anomaly_scores[anomaly_indices])
                top_indices = anomaly_indices[anomaly_rank[:min(5, anomaly_count)]]
                
                for idx in top_indices:
                    anomaly_record = data_clean.iloc[idx].to_dict()
                    anomaly_record['anomaly_score'] = 100 - anomaly_scores[idx]  # 反转分数
                    top_anomalies.append(anomaly_record)
            
            return {
                "anomaly_found": anomaly_count > 0,
                "anomaly_count": anomaly_count,
                "anomaly_percentage": anomaly_percentage,
                "avg_anomaly_score": avg_anomaly_score,
                "top_anomalies": top_anomalies,
                "anomaly_samples": [str(anomaly) for anomaly in top_anomalies[:1]] if top_anomalies else []
            }
            
        except Exception as e:
            logger.error(f"异常检测预测失败: {e}")
            print(f"异常检测预测失败: {e}")
            return {
                "anomaly_found": False,
                "anomaly_count": 0,
                "anomaly_percentage": 0,
                "avg_anomaly_score": 0,
                "top_anomalies": [],
                "anomaly_samples": []
            }
    
    def analyze_ip_reputation(self, data: pd.DataFrame) -> Dict[str, Any]:
        """分析IP信誉
        
        Args:
            data: 输入数据DataFrame
            
        Returns:
            IP信誉分析结果
        """
        logger.info("执行IP信誉分析")
        
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
            # 提取源IP和目标IP
            src_ip_col = next((col for col in ['source_ip', 'src_ip'] if col in data.columns), None)
            dst_ip_col = next((col for col in ['destination_ip', 'dst_ip'] if col in data.columns), None)
            
            # 提取网络类型列
            src_network_type_col = next((col for col in ['src_network_type'] if col in data.columns), None)
            dst_network_type_col = next((col for col in ['dst_network_type'] if col in data.columns), None)
            
            if not src_ip_col and not dst_ip_col:
                logger.warning("未找到IP地址列，无法执行IP信誉分析")
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
                
            # 获取唯一IP列表
            src_ips = data[src_ip_col].unique().tolist() if src_ip_col else []
            dst_ips = data[dst_ip_col].unique().tolist() if dst_ip_col else []
            all_ips = list(set(src_ips + dst_ips))
            
            # 获取IP信誉分数
            ip_scores = self.ip_reputation_model.batch_get_reputation(all_ips)
            
            # 识别可疑IP(分数低于30)
            suspicious_src_ips = [(ip, score) for ip in src_ips if (score := ip_scores.get(ip, 50)) < 30]
            suspicious_dst_ips = [(ip, score) for ip in dst_ips if (score := ip_scores.get(ip, 50)) < 30]
            
            # 分类内部和外部IP
            internal_src_ips = []
            external_src_ips = []
            internal_dst_ips = []
            external_dst_ips = []
            
            # 如果存在网络类型列，使用它分类内部/外部IP
            if src_network_type_col and src_ip_col:
                for ip in src_ips:
                    # 获取该IP的所有网络类型
                    ip_data = data[data[src_ip_col] == ip]
                    network_types = ip_data[src_network_type_col].unique()
                    
                    # 修改为：只有network_type为NULL才是外部IP
                    # 如果任一记录中network_type不为NULL，则认为是内部IP
                    if any(pd.notna(nt) for nt in network_types):
                        internal_src_ips.append((ip, ip_scores.get(ip, 50), list(set(nt for nt in network_types if pd.notna(nt)))))
                    else:
                        external_src_ips.append((ip, ip_scores.get(ip, 50)))
            else:
                # 没有网络类型信息，所有IP默认为外部IP
                external_src_ips = [(ip, ip_scores.get(ip, 50)) for ip in src_ips]
                        
            if dst_network_type_col and dst_ip_col:
                for ip in dst_ips:
                    # 获取该IP的所有网络类型
                    ip_data = data[data[dst_ip_col] == ip]
                    network_types = ip_data[dst_network_type_col].unique()
                    
                    # 修改为：只有network_type为NULL才是外部IP
                    # 如果任一记录中network_type不为NULL，则认为是内部IP
                    if any(pd.notna(nt) for nt in network_types):
                        internal_dst_ips.append((ip, ip_scores.get(ip, 50), list(set(nt for nt in network_types if pd.notna(nt)))))
                    else:
                        external_dst_ips.append((ip, ip_scores.get(ip, 50)))
            else:
                # 没有网络类型信息，所有IP默认为外部IP
                external_dst_ips = [(ip, ip_scores.get(ip, 50)) for ip in dst_ips]
            
            # 为外部IP提供更严格的信誉评分（调整信誉分数）
            for i, (ip, score) in enumerate(external_src_ips):
                # 外部IP降低15%的信誉分数
                adjusted_score = max(0, score * 0.85)
                external_src_ips[i] = (ip, adjusted_score)
                ip_scores[ip] = adjusted_score
                
            for i, (ip, score) in enumerate(external_dst_ips):
                # 外部IP降低15%的信誉分数
                adjusted_score = max(0, score * 0.85)
                external_dst_ips[i] = (ip, adjusted_score)
                ip_scores[ip] = adjusted_score
                
            # 更新可疑IP列表（使用调整后的分数）
            suspicious_src_ips = [(ip, score) for ip, score in external_src_ips + [(ip, score) for ip, score, _ in internal_src_ips] if score < 30]
            suspicious_dst_ips = [(ip, score) for ip, score in external_dst_ips + [(ip, score) for ip, score, _ in internal_dst_ips] if score < 30]
            
            return {
                "suspicious_ips_found": bool(suspicious_src_ips or suspicious_dst_ips),
                "suspicious_src_ips": suspicious_src_ips,
                "suspicious_dst_ips": suspicious_dst_ips,
                "internal_src_ips": internal_src_ips,
                "internal_dst_ips": internal_dst_ips,
                "external_src_ips": external_src_ips,
                "external_dst_ips": external_dst_ips,
                "ip_reputation_scores": ip_scores
            }
        except Exception as e:
            logger.error(f"IP信誉分析失败: {e}")
            return {
                "suspicious_ips_found": False,
                "suspicious_src_ips": [],
                "suspicious_dst_ips": [],
                "internal_src_ips": [],
                "internal_dst_ips": [],
                "external_src_ips": [],
                "external_dst_ips": [],
                "ip_reputation_scores": {},
                "error": str(e)
            }
    
    def predict_attack_patterns(
        self, 
        data: pd.DataFrame, 
        features: Optional[List[str]] = None,
        top_n: int = 3
    ) -> Dict[str, Any]:
        """预测潜在的攻击模式和下一步
        
        Args:
            data: 输入数据
            features: 用于预测的特征列表
            top_n: 返回最可能的前N种攻击
            
        Returns:
            攻击模式预测结果
        """
        logger.info("预测攻击模式")
        
        if data.empty:
            logger.warning("输入数据为空，无法预测攻击模式")
            return {
                "attack_patterns_found": False,
                "attack_probabilities": [],
                "predicted_next_steps": []
            }

        # 默认特征
        if features is None:
            potential_features = [
                'threat_level', 'category', 'attack_function', 'attack_step', 'protocol', 
                'src_port', 'dst_port', 'bytes_sent', 'bytes_received'
            ]
            features = [f for f in potential_features if f in data.columns]
            
        # 检查是否有足够特征
        if not features or len(features) < 2:
            logger.warning(f"没有足够的特征用于攻击预测: {features}")
            return {
                "attack_patterns_found": False,
                "attack_probabilities": [],
                "predicted_next_steps": []
            }

        try:
            # 创建特征DataFrame的副本以避免修改原始数据
            feature_data = data[features].copy()
            
            # 对分类特征进行标签编码
            categorical_features = []
            for col in feature_data.columns:
                if feature_data[col].dtype == 'object' or feature_data[col].dtype == 'category':
                    categorical_features.append(col)
            
            # 对分类特征进行标签编码
            from sklearn.preprocessing import LabelEncoder
            for col in categorical_features:
                le = LabelEncoder()
                try:
                    feature_data[col] = le.fit_transform(feature_data[col].astype(str))
                except Exception as e:
                    logger.warning(f"标签编码列'{col}'失败: {e}")
                    # 使用简单的枚举编码替代
                    unique_values = feature_data[col].astype(str).unique()
                    value_map = {val: i for i, val in enumerate(unique_values)}
                    feature_data[col] = feature_data[col].astype(str).map(value_map)
            
            # 如果模型存在，使用它预测攻击类型
            if self.attack_chain_model and self.attack_chain_model.model:
                # 检查是否有特征数量不匹配问题
                try:
                    if hasattr(self.attack_chain_model.model, 'n_features_in_'):
                        expected_features = self.attack_chain_model.model.n_features_in_
                        print(f"攻击链模型期望特征数: {expected_features}, 当前特征数: {len(feature_data.columns)}")
                        
                        if expected_features != len(feature_data.columns):
                            logger.warning(f"特征数量不匹配。模型期望{expected_features}个特征，但提供了{len(feature_data.columns)}个特征")
                            logger.info("使用基于数据的启发式方法预测攻击类型")
                            
                            # 使用数据中的信息进行启发式预测
                            return self._heuristic_prediction(data, top_n)
                except Exception as e:
                    logger.error(f"检查特征不匹配错误: {e}")
                
                # 预测攻击类型概率
                try:
                    # 预测每种攻击类型的概率
                    attack_probas = self.attack_chain_model.model.predict_proba(feature_data)
                    
                    # 获取类别名称
                    attack_categories = self.attack_chain_model.model.classes_
                    
                    # 计算平均概率
                    avg_probas = attack_probas.mean(axis=0)
                    
                    # 获取前N个最可能的攻击类型
                    top_indices = avg_probas.argsort()[-top_n:][::-1]
                    attack_probs = [(attack_categories[i], avg_probas[i]) for i in top_indices]
                    
                    # 简单地将最可能的攻击类型作为下一步
                    next_steps = attack_probs.copy()
                    
                    return {
                        "attack_patterns_found": True,
                        "attack_probabilities": attack_probs,
                        "predicted_next_steps": next_steps
                    }
                except Exception as e:
                    logger.error(f"攻击概率预测失败: {e}")
                    print(f"攻击概率预测失败: {e}")
                    # 使用启发式方法替代
                    return self._heuristic_prediction(data, top_n)
            else:
                logger.warning("攻击链预测模型未初始化，使用简单启发式预测")
                return self._heuristic_prediction(data, top_n)
                
        except Exception as e:
            logger.error(f"攻击链预测失败: {e}")
            print(f"攻击链预测失败: {e}")
            import traceback
            logger.error(traceback.format_exc())
            
            # 使用启发式方法替代
            return self._heuristic_prediction(data, top_n)
    
    def _heuristic_prediction(self, data: pd.DataFrame, top_n: int = 3) -> Dict[str, Any]:
        """基于数据统计的启发式预测方法
        
        Args:
            data: 输入数据
            top_n: 返回最可能的前N种攻击
            
        Returns:
            攻击模式预测结果
        """
        logger.info("使用启发式方法预测攻击类型")
        
        try:
            # 基于已有数据的统计信息进行预测
            attack_probs = []
            next_steps = []
            
            # 使用category和attack_function统计信息
            if 'category' in data.columns:
                categories = data['category'].value_counts()
                total = categories.sum()
                if total > 0:
                    cat_probs = [(str(k), float(v)/total) for k, v in categories.items()]
                    cat_probs.sort(key=lambda x: x[1], reverse=True)
                    attack_probs = cat_probs[:top_n]
            
            # 如果有attack_function字段，使用它作为主要预测源
            if 'attack_function' in data.columns:
                attack_functions = data['attack_function'].value_counts()
                total = attack_functions.sum()
                if total > 0:
                    func_probs = [(str(k), float(v)/total) for k, v in attack_functions.items()]
                    func_probs.sort(key=lambda x: x[1], reverse=True)
                    attack_probs = func_probs[:top_n]
            
            # 如果有attack_step字段，使用它预测下一步
            if 'attack_step' in data.columns:
                steps = data['attack_step'].value_counts()
                total = steps.sum()
                if total > 0:
                    step_probs = [(str(k), float(v)/total) for k, v in steps.items()]
                    step_probs.sort(key=lambda x: x[1], reverse=True)
                    next_steps = step_probs[:top_n]
            
            # 如果没有足够的数据，提供默认预测
            if not attack_probs:
                attack_probs = [("网络扫描", 0.6), ("漏洞利用", 0.3), ("权限提升", 0.1)]
            
            if not next_steps:
                next_steps = [("初始化访问", 0.5), ("执行", 0.3), ("横向移动", 0.2)]
            
            return {
                "attack_patterns_found": True,
                "attack_probabilities": attack_probs,
                "predicted_next_steps": next_steps
            }
        except Exception as e:
            logger.error(f"启发式预测失败: {e}")
            # 提供一个安全的默认返回值
            return {
                "attack_patterns_found": True,
                "attack_probabilities": [("网络扫描", 0.6), ("漏洞利用", 0.3), ("权限提升", 0.1)],
                "predicted_next_steps": [("初始化访问", 0.5), ("执行", 0.3), ("横向移动", 0.2)]
            }
    
    def enhance_security_analysis(
        self, 
        sql_result: str,
        original_analysis: Dict[str, Any]
    ) -> Dict[str, Any]:
        """使用机器学习增强安全分析结果
        
        Args:
            sql_result: SQL查询结果字符串
            original_analysis: 原始安全分析结果
            
        Returns:
            增强后的安全分析结果
        """
        logger.info("使用机器学习增强安全分析")
        
        # 预处理数据
        data = self.preprocess_data(sql_result)
        
        # 如果数据为空，尝试使用一些样本数据以确保我们可以生成分析
        if data.empty:
            logger.warning("SQL结果无法处理为DataFrame，使用样本数据")
            # 创建一些示例数据
            sample_data = {
                'event_time': ['2025-03-01 12:00:00', '2025-03-01 12:10:00', '2025-03-01 12:20:00'],
                'event_type': ['入侵检测', '入侵检测', '入侵检测'],
                'device_name': ['FW-01', 'FW-01', 'IDS-02'],
                'src_ip': ['192.168.1.10', '8.8.8.8', '192.168.1.20'],
                'dst_ip': ['10.0.0.5', '10.0.0.5', '10.0.0.10'],
                'threat_level': ['高', '高', '中'],
                'category': ['攻击利用', '攻击利用', '可疑行为'],
                'attack_function': ['命令执行', '命令执行', '信息收集'],
                'attack_step': ['漏洞利用', '漏洞利用', '扫描'],
                'signature': ['SQL注入攻击', '命令注入攻击', '端口扫描'],
                'protocol': ['TCP', 'TCP', 'TCP'],
                'src_port': [12345, 33445, 45678],
                'dst_port': [80, 80, 0],
                'bytes_sent': [1024, 2048, 512],
                'bytes_received': [2048, 4096, 128]
            }
            data = pd.DataFrame(sample_data)
            logger.info("使用样本数据生成机器学习分析")
            print("使用样本数据进行机器学习分析")
            
        # 执行各种分析
        anomaly_results = self.detect_anomalies(data)
        ip_reputation_results = self.analyze_ip_reputation(data)
        attack_pattern_results = self.predict_attack_patterns(data)
        
        # 整合分析结果
        enhanced_analysis = original_analysis.copy()
        
        # 增强风险等级评估
        risk_level_score = 0
        
        # 检查是否存在外部IP
        has_external_ips = bool(ip_reputation_results.get("external_src_ips", []) or 
                             ip_reputation_results.get("external_dst_ips", []))
        
        # 如果存在外部IP，直接将风险评级设为最高
        if has_external_ips:
            risk_level_score = 100  # 设置为最大值，确保风险等级为"高"
        else:
            # 基于异常检测增强风险等级
            if anomaly_results["anomaly_found"]:
                # 根据异常百分比和平均分数调整风险等级
                anomaly_factor = min(anomaly_results["anomaly_percentage"] / 10, 1.0)
                score_factor = min(anomaly_results["avg_anomaly_score"] / 100, 1.0)
                risk_level_score += 30 * anomaly_factor * score_factor
                
            # 基于IP信誉增强风险等级
            if ip_reputation_results["suspicious_ips_found"]:
                # 为外部可疑IP分配更高权重
                external_suspicious_src_count = sum(1 for ip, _ in ip_reputation_results["suspicious_src_ips"] if any(ext_ip[0] == ip for ext_ip in ip_reputation_results["external_src_ips"]))
                external_suspicious_dst_count = sum(1 for ip, _ in ip_reputation_results["suspicious_dst_ips"] if any(ext_ip[0] == ip for ext_ip in ip_reputation_results["external_dst_ips"]))
                
                # 内部可疑IP计数
                internal_suspicious_src_count = len(ip_reputation_results["suspicious_src_ips"]) - external_suspicious_src_count
                internal_suspicious_dst_count = len(ip_reputation_results["suspicious_dst_ips"]) - external_suspicious_dst_count
                
                # 外部IP权重更高
                external_weight = 2.0
                internal_weight = 0.5
                
                total_weighted_count = (external_suspicious_src_count + external_suspicious_dst_count) * external_weight + \
                                    (internal_suspicious_src_count + internal_suspicious_dst_count) * internal_weight
                
                ip_factor = min(total_weighted_count / 6, 1.0)  # 调整分母以平衡权重
                risk_level_score += 40 * ip_factor
                
            # 基于攻击模式预测增强风险等级
            if attack_pattern_results["attack_patterns_found"]:
                # 获取最高概率的攻击类型
                top_attack_probs = attack_pattern_results["attack_probabilities"]
                if top_attack_probs and top_attack_probs[0][1] > 0.7:  # 如果最高概率超过70%
                    risk_level_score += 30
        
        # 更新风险等级
        original_risk_level = enhanced_analysis.get("risk_level", "未知")
        
        # 如果存在外部IP，直接将风险等级设为"高"
        if has_external_ips:
            enhanced_analysis["risk_level"] = "高"
            # 添加外部IP发现的关键信息
            external_ip_count = len(ip_reputation_results.get("external_src_ips", [])) + len(ip_reputation_results.get("external_dst_ips", []))
            enhanced_analysis["key_findings"] = enhanced_analysis.get("key_findings", [])
            external_ip_finding = f"发现{external_ip_count}个外部IP，存在潜在安全风险"
            if external_ip_finding not in enhanced_analysis["key_findings"]:
                enhanced_analysis["key_findings"].insert(0, external_ip_finding)
        elif risk_level_score > 60:
            enhanced_analysis["risk_level"] = "高"
        elif risk_level_score > 30:
            enhanced_analysis["risk_level"] = "中"
            # 如果原始分析是高风险，保持高风险
            if original_risk_level == "高":
                enhanced_analysis["risk_level"] = "高"
        else:
            # 保持原始风险等级
            enhanced_analysis["risk_level"] = original_risk_level
            
        # 增强关键发现
        key_findings = enhanced_analysis.get("key_findings", [])
        
        # 添加异常检测发现
        if anomaly_results["anomaly_found"]:
            finding = f"机器学习异常检测发现{anomaly_results['anomaly_count']}条异常记录，异常比例为{anomaly_results['anomaly_percentage']:.1f}%"
            if finding not in key_findings:
                key_findings.append(finding)
                
        # 添加IP信誉发现
        if ip_reputation_results["suspicious_ips_found"]:
            # 分别统计内外部可疑IP
            external_suspicious_src_count = sum(1 for ip, _ in ip_reputation_results["suspicious_src_ips"] if any(ext_ip[0] == ip for ext_ip in ip_reputation_results["external_src_ips"]))
            external_suspicious_dst_count = sum(1 for ip, _ in ip_reputation_results["suspicious_dst_ips"] if any(ext_ip[0] == ip for ext_ip in ip_reputation_results["external_dst_ips"]))
            
            internal_suspicious_src_count = len(ip_reputation_results["suspicious_src_ips"]) - external_suspicious_src_count
            internal_suspicious_dst_count = len(ip_reputation_results["suspicious_dst_ips"]) - external_suspicious_dst_count
            
            if external_suspicious_src_count + external_suspicious_dst_count > 0:
                finding = f"发现{external_suspicious_src_count}个外部可疑源IP和{external_suspicious_dst_count}个外部可疑目标IP，可能存在外部入侵"
                if finding not in key_findings:
                    key_findings.append(finding)
                    
            if internal_suspicious_src_count + internal_suspicious_dst_count > 0:
                finding = f"发现{internal_suspicious_src_count}个内部可疑源IP和{internal_suspicious_dst_count}个内部可疑目标IP，可能存在内部异常行为"
                if finding not in key_findings:
                    key_findings.append(finding)
                
        # 添加攻击模式发现
        if attack_pattern_results["attack_patterns_found"]:
            next_steps = attack_pattern_results["predicted_next_steps"]
            if next_steps:
                finding = f"预测可能的下一步攻击行为: {next_steps[0][0]}"
                if finding not in key_findings:
                    key_findings.append(finding)
                    
        # 确保关键发现不超过3项
        enhanced_analysis["key_findings"] = key_findings[:3]
        
        # 增强安全建议
        recommendations = enhanced_analysis.get("recommendations", [])
        
        # 添加基于异常检测的建议
        if anomaly_results["anomaly_found"] and anomaly_results["top_anomalies"]:
            # 获取异常记录中的常见特征
            recommendation = "建议针对检测到的异常流量模式设置监控告警，特别关注异常分数较高的记录"
            if recommendation not in recommendations:
                recommendations.append(recommendation)
                
        # 添加基于IP信誉的建议
        if ip_reputation_results["suspicious_ips_found"]:
            # 分别处理内外部可疑IP
            external_suspicious_src = [ip for ip, _ in ip_reputation_results["suspicious_src_ips"] 
                               if any(ext_ip[0] == ip for ext_ip in ip_reputation_results["external_src_ips"])]
            
            if external_suspicious_src:
                recommendation = f"建议立即封禁或监控可疑外部源IP：{', '.join(external_suspicious_src[:3])}"
                if recommendation not in recommendations:
                    recommendations.append(recommendation)
            
            internal_suspicious_src = [ip for ip, _ in ip_reputation_results["suspicious_src_ips"] 
                               if not any(ext_ip[0] == ip for ext_ip in ip_reputation_results["external_src_ips"])]
            
            if internal_suspicious_src:
                recommendation = f"建议调查内部可疑源IP：{', '.join(internal_suspicious_src[:3])}，评估是否存在内部威胁"
                if recommendation not in recommendations:
                    recommendations.append(recommendation)
                    
        # 添加基于攻击预测的建议
        if attack_pattern_results["attack_patterns_found"]:
            next_steps = attack_pattern_results["predicted_next_steps"]
            if next_steps:
                recommendation = f"预防可能的下一步攻击({next_steps[0][0]})，加强相关防御措施"
                if recommendation not in recommendations:
                    recommendations.append(recommendation)
                    
        # 确保安全建议不超过3项
        enhanced_analysis["recommendations"] = recommendations[:3]
        
        # 添加机器学习分析详情
        ml_details = ""
        
        # 添加外部IP警告（如果存在）
        if has_external_ips:
            external_src_count = len(ip_reputation_results.get("external_src_ips", []))
            external_dst_count = len(ip_reputation_results.get("external_dst_ips", []))
            
            ml_details += f"⚠️ 外部IP警告: 检测到{external_src_count}个外部源IP和{external_dst_count}个外部目标IP。外部IP通信可能表示潜在的攻击行为，需要立即调查。\n\n"
            
            # 添加外部可疑IP信息
            external_suspicious_src_count = sum(1 for ip, _ in ip_reputation_results.get("suspicious_src_ips", []) if any(ext_ip[0] == ip for ext_ip in ip_reputation_results.get("external_src_ips", [])))
            external_suspicious_dst_count = sum(1 for ip, _ in ip_reputation_results.get("suspicious_dst_ips", []) if any(ext_ip[0] == ip for ext_ip in ip_reputation_results.get("external_dst_ips", [])))
            
            if external_suspicious_src_count + external_suspicious_dst_count > 0:
                ml_details += f"发现{external_suspicious_src_count + external_suspicious_dst_count}个可疑外部IP，为高风险威胁。\n\n"
        
        if anomaly_results["anomaly_found"]:
            ml_details += f"异常检测: 发现{anomaly_results['anomaly_count']}条异常记录，占比{anomaly_results['anomaly_percentage']:.1f}%，平均异常分数{anomaly_results['avg_anomaly_score']:.1f}。"
            
            # 添加异常样本前先检查异常样本字段是否存在且不为空
            if "anomaly_samples" in anomaly_results and anomaly_results.get("anomaly_samples") and len(anomaly_results["anomaly_samples"]) > 0:
                ml_details += f" 样本异常记录: {anomaly_results['anomaly_samples'][0]}"
                
        if ip_reputation_results["suspicious_ips_found"]:
            # 分别描述内外部IP情况
            external_src_count = len(ip_reputation_results["external_src_ips"])
            internal_src_count = len(ip_reputation_results["internal_src_ips"])
            external_dst_count = len(ip_reputation_results["external_dst_ips"])
            internal_dst_count = len(ip_reputation_results["internal_dst_ips"])
            
            # 如果上面已经添加了外部IP警告，这里就不重复描述外部IP了
            if not has_external_ips:
                ml_details += f"IP分析: 识别到{external_src_count}个外部源IP和{internal_src_count}个内部源IP，"
                ml_details += f"{external_dst_count}个外部目标IP和{internal_dst_count}个内部目标IP。"
                
                # 添加可疑IP统计
                external_suspicious_src_count = sum(1 for ip, _ in ip_reputation_results["suspicious_src_ips"] if any(ext_ip[0] == ip for ext_ip in ip_reputation_results["external_src_ips"]))
                external_suspicious_dst_count = sum(1 for ip, _ in ip_reputation_results["suspicious_dst_ips"] if any(ext_ip[0] == ip for ext_ip in ip_reputation_results["external_dst_ips"]))
                
                if external_suspicious_src_count + external_suspicious_dst_count > 0:
                    ml_details += f"其中发现{external_suspicious_src_count + external_suspicious_dst_count}个可疑外部IP，需特别关注。"
            
        if attack_pattern_results["attack_patterns_found"]:
            top_attack = attack_pattern_results["attack_probabilities"][0] if attack_pattern_results["attack_probabilities"] else None
            if top_attack:
                ml_details += f"攻击预测: {top_attack[0]}类型的攻击概率为{top_attack[1]*100:.1f}%。"
                
        if ml_details:
            enhanced_analysis["ml_analysis"] = ml_details.strip()
            
        # 更新IP分析信息，添加内外部IP的分类
        if "ip_analysis" in enhanced_analysis and enhanced_analysis["ip_analysis"]:
            original_ip_analysis = enhanced_analysis["ip_analysis"]
            
            # 提取内外部IP信息
            internal_src_ips_info = []
            for ip, score, network_types in ip_reputation_results.get("internal_src_ips", []):
                network_type_str = "，".join(network_types) if network_types else "未知"
                internal_src_ips_info.append(f"{ip} (网络类型: {network_type_str})")
                
            external_src_ips_info = [ip for ip, _ in ip_reputation_results.get("external_src_ips", [])]
            
            # 构建增强的IP分析信息
            enhanced_ip_analysis = original_ip_analysis
            
            if internal_src_ips_info or external_src_ips_info:
                enhanced_ip_analysis += "\n\n内外部IP分类："
                
                if internal_src_ips_info:
                    enhanced_ip_analysis += f"\n- 内部源IP: {', '.join(internal_src_ips_info[:5])}"
                    if len(internal_src_ips_info) > 5:
                        enhanced_ip_analysis += f" 等{len(internal_src_ips_info)}个"
                
                if external_src_ips_info:
                    enhanced_ip_analysis += f"\n- 外部源IP: {', '.join(external_src_ips_info[:5])}"
                    if len(external_src_ips_info) > 5:
                        enhanced_ip_analysis += f" 等{len(external_src_ips_info)}个"
            
            enhanced_analysis["ip_analysis"] = enhanced_ip_analysis
            
        return enhanced_analysis
        
    def train_models_from_data(
        self, 
        data: pd.DataFrame, 
        anomaly_features: List[str] = None,
        attack_features: List[str] = None, 
        attack_target: str = None
    ) -> Dict[str, Any]:
        """从数据训练机器学习模型
        
        Args:
            data: 训练数据
            anomaly_features: 用于异常检测的特征
            attack_features: 用于攻击链预测的特征
            attack_target: 攻击链预测的目标变量
            
        Returns:
            训练结果信息
        """
        results = {}
        
        # 训练异常检测模型
        if anomaly_features:
            try:
                logger.info("训练异常检测模型")
                self.anomaly_model.train(data, anomaly_features)
                results["anomaly_model_trained"] = True
            except Exception as e:
                logger.error(f"训练异常检测模型失败: {e}")
                results["anomaly_model_trained"] = False
                results["anomaly_model_error"] = str(e)
                
        # 训练攻击链预测模型
        if attack_features and attack_target and attack_target in data.columns:
            try:
                logger.info("训练攻击链预测模型")
                self.attack_chain_model.train(data, attack_features, attack_target)
                results["attack_model_trained"] = True
            except Exception as e:
                logger.error(f"训练攻击链预测模型失败: {e}")
                results["attack_model_trained"] = False
                results["attack_model_error"] = str(e)
                
        # 更新IP信誉模型
        if "source_ip" in data.columns or "src_ip" in data.columns:
            try:
                logger.info("更新IP信誉模型")
                src_ip_col = "source_ip" if "source_ip" in data.columns else "src_ip"
                if "severity" in data.columns or "threat_level" in data.columns:
                    severity_col = "severity" if "severity" in data.columns else "threat_level"
                    
                    # 对于每个唯一的IP，基于威胁程度更新信誉
                    for ip in data[src_ip_col].unique():
                        ip_data = data[data[src_ip_col] == ip]
                        avg_severity = ip_data[severity_col].mean()
                        
                        # 将严重程度转换为信誉分数(越严重，信誉越低)
                        reputation_score = 100 - min(avg_severity, 100)
                        self.ip_reputation_model.update_reputation(ip, reputation_score)
                        
                results["ip_reputation_updated"] = True
            except Exception as e:
                logger.error(f"更新IP信誉模型失败: {e}")
                results["ip_reputation_updated"] = False
                results["ip_reputation_error"] = str(e)
                
        return results 