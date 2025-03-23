"""
调试模型训练功能，确保使用正确的特征和目标
"""
import os
import pandas as pd
import numpy as np
import pickle
from pathlib import Path
import json
import requests
import logging
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

# 设置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# API请求URL
url = "http://localhost:8000/api/v1/ml/train"

def debug_model_training():
    """调试模型训练过程"""
    logger.info("开始调试模型训练过程...")
    
    try:
        # 从数据库获取训练数据
        from sqlalchemy import create_engine, text
        from security_agent.config import settings
        
        # 创建数据库引擎
        engine = create_engine(settings.DB_CONNECTION_STRING)
        logger.info(f"成功连接到数据库: {settings.DB_CONNECTION_STRING}")
        
        # 查询训练数据
        with engine.connect() as conn:
            query = """
            SELECT 
                event_time, event_type, device_name, src_ip, threat_level, 
                category, attack_function, attack_step, signature, dst_ip, protocol,
                src_port, dst_port, bytes_to_server as bytes_sent, bytes_to_client as bytes_received
            FROM ids_ai
            LIMIT 2000
            """
            result = conn.execute(text(query))
            df = pd.DataFrame(result.fetchall(), columns=result.keys())
            
        logger.info(f"获取到{len(df)}条训练数据")
        
        # 显示数据信息
        logger.info(f"数据列名: {list(df.columns)}")
        
        # 查看分类列的值分布
        logger.info(f"attack_function值分布: {df['attack_function'].value_counts().to_dict()}")
        logger.info(f"attack_step值分布: {df['attack_step'].value_counts().to_dict()}")
        logger.info(f"category值分布: {df['category'].value_counts().to_dict()}")
        
        # 保存原始数据
        raw_csv_path = 'debug_raw_data.csv'
        df.to_csv(raw_csv_path, index=False)
        logger.info(f"原始数据已保存到 {raw_csv_path}")
        
        # 预处理数据
        df_processed = df.copy()
        
        # 填充空值
        for col in df_processed.columns:
            if df_processed[col].dtype == 'object' or df_processed[col].dtype == 'category':
                if df_processed[col].isna().sum() > 0:
                    logger.info(f"列'{col}'有{df_processed[col].isna().sum()}个空值，进行填充")
                    df_processed[col] = df_processed[col].fillna('未知')
        
        # 编码分类特征
        encoded_features = {}
        categorical_features = ['category', 'attack_function', 'attack_step', 'signature', 'protocol']
        
        for feature in categorical_features:
            if feature in df_processed.columns:
                # 创建并保存编码器
                le = LabelEncoder()
                df_processed[feature + '_encoded'] = le.fit_transform(df_processed[feature])
                
                # 保存编码映射，用于检查
                mapping = dict(zip(le.classes_, le.transform(le.classes_)))
                encoded_features[feature] = mapping
                
                logger.info(f"'{feature}'列编码完成，值映射: {mapping}")
        
        # 保存处理后的数据
        processed_csv_path = 'debug_processed_data.csv'
        df_processed.to_csv(processed_csv_path, index=False)
        logger.info(f"处理后的数据已保存到 {processed_csv_path}")
        
        # 保存编码映射
        with open('feature_encodings.json', 'w') as f:
            json.dump(encoded_features, f, ensure_ascii=False, indent=2)
        logger.info("特征编码映射已保存到 feature_encodings.json")
        
        # 准备特征和目标变量
        numeric_columns = df_processed.select_dtypes(include=['number']).columns.tolist()
        logger.info(f"数值列: {numeric_columns}")
        
        # 移除不需要的特征
        numeric_columns = [col for col in numeric_columns if not col.endswith('_encoded')]
        logger.info(f"用于异常检测的数值列: {numeric_columns}")
        
        # 准备攻击链特征
        encoded_cols = [f + '_encoded' for f in categorical_features if f + '_encoded' in df_processed.columns]
        attack_features = numeric_columns + encoded_cols
        logger.info(f"用于攻击链预测的特征: {attack_features}")
        
        # 确保attack_function_encoded存在
        if 'attack_function_encoded' not in df_processed.columns:
            logger.error("attack_function_encoded列不存在！模型训练可能会失败")
        else:
            logger.info(f"attack_function_encoded列存在，值范围: {df_processed['attack_function_encoded'].min()} - {df_processed['attack_function_encoded'].max()}")
            logger.info(f"attack_function_encoded值分布: {df_processed['attack_function_encoded'].value_counts().to_dict()}")
        
        # 手动训练模型
        logger.info("开始手动训练攻击链预测模型...")
        
        # 准备数据
        X = df_processed[attack_features].values
        
        # 确保目标变量正确
        target_column = 'attack_function_encoded'  # 使用默认目标
        
        if target_column in df_processed.columns:
            y = df_processed[target_column].values
            
            # 划分训练集和测试集
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
            
            # 训练模型
            model = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42)
            model.fit(X_train, y_train)
            
            # 评估模型
            accuracy = model.score(X_test, y_test)
            logger.info(f"模型训练完成，测试准确率: {accuracy:.4f}")
            
            # 查看模型类别
            classes = model.classes_
            logger.info(f"模型类别: {classes}")
            
            # 类别映射回原始值
            inverse_mapping = {v: k for k, v in encoded_features['attack_function'].items()}
            original_classes = [inverse_mapping.get(c, f"未知_{c}") for c in classes]
            logger.info(f"原始类别名称: {original_classes}")
            
            # 保存模型
            MODEL_DIR = Path("./models")
            MODEL_DIR.mkdir(exist_ok=True)
            
            # 保存模型数据
            model_data = {
                'model': model,
                'scaler': None  # 暂时不使用scaler
            }
            
            model_path = os.path.join(MODEL_DIR, "debug_attack_model.pkl")
            with open(model_path, 'wb') as f:
                pickle.dump(model_data, f)
            logger.info(f"模型保存到 {model_path}")
            
            # 验证模型
            logger.info("验证模型预测...")
            sample_features = X_test[:5]
            predictions = model.predict(sample_features)
            probabilities = model.predict_proba(sample_features)
            
            logger.info("样本预测结果:")
            for i, pred in enumerate(predictions):
                probs = probabilities[i]
                max_prob = probs.max()
                original_class = inverse_mapping.get(pred, f"未知_{pred}")
                logger.info(f"样本 {i+1}: 预测 {original_class} (类别ID: {pred}), 概率: {max_prob:.4f}")
        else:
            logger.error(f"目标列 '{target_column}' 不存在，无法训练模型")
        
        # 使用API训练模型
        logger.info("\n使用API接口训练模型...")
        
        with open(processed_csv_path, 'rb') as f:
            files = {'file': (os.path.basename(processed_csv_path), f, 'text/csv')}
            
            # 确保使用正确的特征和目标
            form_data = {
                "anomaly_features": json.dumps(numeric_columns),
                "attack_features": json.dumps(attack_features),
                "attack_target": target_column
            }
            
            logger.info(f"API请求参数: {form_data}")
            
            response = requests.post(
                url, 
                files=files,
                data=form_data
            )
        
        # 检查响应
        logger.info(f"响应状态码: {response.status_code}")
        
        if response.status_code == 200:
            result = response.json()
            logger.info("\n训练结果:")
            logger.info(json.dumps(result, ensure_ascii=False, indent=2))
            
            if result.get("success"):
                logger.info("\n✅ API模型训练成功!")
                
                # 检查模型文件
                models_dir = Path('./models')
                logger.info(f"模型目录内容: {list(models_dir.glob('*.pkl'))}")
                
                # 检查新模型
                new_model_path = os.path.join(models_dir, "attack_chain_model.pkl")
                if os.path.exists(new_model_path):
                    with open(new_model_path, 'rb') as f:
                        new_model_data = pickle.load(f)
                        
                    if hasattr(new_model_data.get('model'), 'classes_'):
                        new_classes = new_model_data['model'].classes_
                        logger.info(f"新模型类别: {new_classes}")
                        
                        # 类别映射回原始值
                        new_original_classes = [inverse_mapping.get(c, f"未知_{c}") for c in new_classes]
                        logger.info(f"新模型原始类别名称: {new_original_classes}")
            else:
                logger.error("\n❌ API模型训练失败!")
        else:
            logger.error(f"请求失败: {response.text}")
            
    except Exception as e:
        import traceback
        logger.error(f"模型训练调试过程中发生错误: {e}")
        logger.error(traceback.format_exc())

if __name__ == "__main__":
    debug_model_training() 