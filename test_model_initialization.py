#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
测试模型初始化问题，定位故障原因
"""
import os
import sys
import logging
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from dotenv import load_dotenv
import pymysql
import traceback
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# 设置日志
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("model_init_test")

# 加载环境变量
try:
    load_dotenv()
    logger.info("环境变量加载成功")
    
    # 打印关键环境变量（隐藏密码）
    db_host = os.getenv("DB_HOST", "localhost")
    db_user = os.getenv("DB_USER", "root")
    db_name = os.getenv("DB_NAME", "itm")
    db_port = os.getenv("DB_PORT", "3306")
    
    logger.info(f"数据库配置: {db_host}:{db_port}/{db_name} (用户: {db_user})")
except Exception as e:
    logger.error(f"加载环境变量失败: {str(e)}")

def connect_to_database():
    """连接到数据库"""
    try:
        # 获取数据库配置
        db_host = os.getenv("DB_HOST", "localhost")
        db_user = os.getenv("DB_USER", "root")
        db_password = os.getenv("DB_PASSWORD", "password")
        db_name = os.getenv("DB_NAME", "itm")
        db_port = int(os.getenv("DB_PORT", "3306"))
        
        logger.info(f"尝试连接数据库: {db_host}:{db_port}/{db_name}")
        
        # 尝试连接
        connection = pymysql.connect(
            host=db_host,
            user=db_user,
            password=db_password,
            database=db_name,
            port=db_port,
            cursorclass=pymysql.cursors.DictCursor
        )
        logger.info(f"成功连接到数据库: {db_name}")
        
        # 检查连接是否有效
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            result = cursor.fetchone()
            logger.info(f"数据库连接测试: {result}")
        
        return connection
    except Exception as e:
        logger.error(f"数据库连接失败: {str(e)}")
        logger.error(traceback.format_exc())
        return None

def check_database_tables():
    """检查数据库中的表"""
    connection = connect_to_database()
    if not connection:
        return
    
    try:
        with connection.cursor() as cursor:
            # 获取所有表
            cursor.execute("SHOW TABLES")
            tables = cursor.fetchall()
            
            logger.info(f"数据库中的表:")
            for table in tables:
                table_name = list(table.values())[0]
                logger.info(f"- {table_name}")
                
                # 获取表记录数
                cursor.execute(f"SELECT COUNT(*) as count FROM {table_name}")
                count = cursor.fetchone()['count']
                logger.info(f"  记录数: {count}")
                
                # 检查ids_ai表的结构
                if table_name == 'ids_ai':
                    cursor.execute(f"DESCRIBE {table_name}")
                    columns = cursor.fetchall()
                    logger.info(f"  表结构:")
                    for column in columns:
                        logger.info(f"  - {column['Field']} ({column['Type']})")
    except Exception as e:
        logger.error(f"检查数据库表失败: {str(e)}")
        logger.error(traceback.format_exc())
    finally:
        connection.close()

def test_simple_query():
    """测试简单的数据库查询"""
    connection = connect_to_database()
    if not connection:
        return
    
    try:
        with connection.cursor() as cursor:
            # 测试简单的ids_ai查询
            query = "SELECT * FROM ids_ai LIMIT 5"
            logger.info(f"执行查询: {query}")
            cursor.execute(query)
            results = cursor.fetchall()
            
            logger.info(f"查询结果: {len(results)}条记录")
            if results:
                for i, row in enumerate(results):
                    logger.info(f"记录 {i+1}: {row}")
    except Exception as e:
        logger.error(f"执行简单查询失败: {str(e)}")
        logger.error(traceback.format_exc())
    finally:
        connection.close()

def fetch_data(hours=1):
    """获取数据库中的安全数据"""
    connection = connect_to_database()
    if not connection:
        return pd.DataFrame()
    
    try:
        with connection.cursor() as cursor:
            end_time = datetime.now()
            start_time = end_time - timedelta(hours=hours)
            
            logger.info(f"查询时间范围: {start_time} 到 {end_time}")
            
            # 首先验证ids_ai表是否存在并有数据
            try:
                cursor.execute("SELECT COUNT(*) as count FROM ids_ai")
                count = cursor.fetchone()['count']
                logger.info(f"ids_ai表中有 {count} 条记录")
            except Exception as e:
                logger.error(f"无法验证ids_ai表: {str(e)}")
                return pd.DataFrame()
            
            # 构建并执行查询
            query = """
            SELECT 
                ids_ai.event_time, 
                ids_ai.src_ip, 
                ids_ai.dst_ip, 
                ids_ai.threat_level, 
                ids_ai.signature,
                ids_ai.src_port,
                ids_ai.dst_port,
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
            LIMIT 100
            """
            
            logger.info(f"执行查询: {query}")
            logger.info(f"参数: {start_time}")
            
            cursor.execute(query, (start_time,))
            results = cursor.fetchall()
            
            # 创建DataFrame
            df = pd.DataFrame(results)
            logger.info(f"成功获取{len(df)}条安全数据")
            
            # 记录数据结构
            if not df.empty:
                logger.info(f"数据列: {df.columns.tolist()}")
                logger.info(f"数据类型: \n{df.dtypes}")
                
                # 检查数值列
                numeric_cols = df.select_dtypes(include=['number']).columns.tolist()
                logger.info(f"数值列: {numeric_cols}")
                
                # 检查缺失值
                null_counts = df.isnull().sum()
                logger.info(f"缺失值统计: \n{null_counts}")
            
            return df
    except Exception as e:
        logger.error(f"获取数据失败: {str(e)}")
        logger.error(traceback.format_exc())
        return pd.DataFrame()
    finally:
        connection.close()

def test_standard_scaler(data):
    """测试StandardScaler初始化和拟合"""
    logger.info("\n=== 测试StandardScaler ===")
    
    # 检查数据是否为空
    if data.empty:
        logger.error("数据为空，无法测试StandardScaler")
        return
    
    # 尝试使用不同的特征组合
    feature_sets = [
        ['threat_level'],
        ['threat_level', 'src_port', 'dst_port'],
        data.select_dtypes(include=['number']).columns.tolist()
    ]
    
    for i, features in enumerate(feature_sets):
        logger.info(f"\n测试特征集 {i+1}: {features}")
        
        try:
            # 检查特征是否存在
            missing_features = [f for f in features if f not in data.columns]
            if missing_features:
                logger.error(f"缺少特征: {missing_features}")
                continue
                
            # 检查数据类型
            for feature in features:
                logger.info(f"特征 {feature} 类型: {data[feature].dtype}")
                
            # 提取特征数据
            X = data[features].values
            logger.info(f"特征数据形状: {X.shape}")
            
            # 检查是否有NaN或Inf
            if np.isnan(X).any() or np.isinf(X).any():
                logger.warning("特征数据中包含NaN或Inf值")
                
                # 填充NaN
                logger.info("尝试填充NaN值")
                X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
            
            # 标准化
            logger.info("创建StandardScaler")
            scaler = StandardScaler()
            
            logger.info("拟合StandardScaler")
            scaler.fit(X)
            
            logger.info("变换数据")
            X_scaled = scaler.transform(X)
            
            logger.info(f"标准化数据形状: {X_scaled.shape}")
            logger.info(f"标准化数据均值: {np.mean(X_scaled, axis=0)}")
            logger.info(f"标准化数据标准差: {np.std(X_scaled, axis=0)}")
            
            logger.info(f"特征集 {i+1} 测试成功\n")
        except Exception as e:
            logger.error(f"特征集 {i+1} 测试失败: {str(e)}")
            logger.error(traceback.format_exc())

def test_isolation_forest(data):
    """测试IsolationForest初始化和拟合"""
    logger.info("\n=== 测试IsolationForest ===")
    
    # 检查数据是否为空
    if data.empty:
        logger.error("数据为空，无法测试IsolationForest")
        return
    
    # 尝试使用不同的特征组合
    feature_sets = [
        ['threat_level'],
        ['threat_level', 'src_port', 'dst_port'],
        data.select_dtypes(include=['number']).columns.tolist()
    ]
    
    for i, features in enumerate(feature_sets):
        logger.info(f"\n测试特征集 {i+1}: {features}")
        
        try:
            # 检查特征是否存在
            missing_features = [f for f in features if f not in data.columns]
            if missing_features:
                logger.error(f"缺少特征: {missing_features}")
                continue
                
            # 提取特征数据
            X = data[features].fillna(0).values
            logger.info(f"特征数据形状: {X.shape}")
            
            # 标准化
            scaler = StandardScaler()
            X_scaled = scaler.fit_transform(X)
            
            # 创建和拟合IsolationForest
            logger.info("创建IsolationForest")
            model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
            
            logger.info("拟合IsolationForest")
            model.fit(X_scaled)
            
            # 预测
            logger.info("使用模型预测")
            predictions = model.predict(X_scaled)
            anomaly_scores = model.decision_function(X_scaled)
            
            logger.info(f"预测形状: {predictions.shape}")
            logger.info(f"异常数量: {np.sum(predictions == -1)}")
            logger.info(f"异常比例: {np.sum(predictions == -1) / len(predictions) * 100:.2f}%")
            logger.info(f"异常分数范围: [{anomaly_scores.min():.2f}, {anomaly_scores.max():.2f}]")
            
            logger.info(f"特征集 {i+1} 测试成功\n")
        except Exception as e:
            logger.error(f"特征集 {i+1} 测试失败: {str(e)}")
            logger.error(traceback.format_exc())

def test_full_pipeline(data):
    """测试完整的异常检测流水线"""
    logger.info("\n=== 测试完整异常检测流水线 ===")
    
    # 检查数据是否为空
    if data.empty:
        logger.error("数据为空，无法测试完整流水线")
        return
    
    try:
        # 1. 选择特征
        logger.info("1. 选择特征")
        features = ['threat_level']
        
        # 检查特征是否存在
        missing_features = [f for f in features if f not in data.columns]
        if missing_features:
            # 尝试使用其他数值特征
            logger.warning(f"缺少特征: {missing_features}，尝试使用其他数值特征")
            features = data.select_dtypes(include=['number']).columns.tolist()
            
            if not features:
                logger.error("没有可用的数值特征")
                return
        
        logger.info(f"使用特征: {features}")
        
        # 2. 数据准备
        logger.info("2. 数据准备")
        X = data[features].fillna(0).values
        logger.info(f"特征数据形状: {X.shape}")
        
        # 3. 标准化
        logger.info("3. 数据标准化")
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        
        # 4. 异常检测
        logger.info("4. 异常检测")
        model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
        model.fit(X_scaled)
        
        # 5. 预测异常
        logger.info("5. 预测异常")
        predictions = model.predict(X_scaled)
        anomaly_scores = model.decision_function(X_scaled)
        
        # 6. 生成结果
        logger.info("6. 生成结果")
        anomalies = predictions == -1
        anomaly_count = np.sum(anomalies)
        anomaly_percentage = 100 * anomaly_count / len(data) if len(data) > 0 else 0
        
        # 7. 输出统计
        logger.info(f"异常数量: {anomaly_count}")
        logger.info(f"异常比例: {anomaly_percentage:.2f}%")
        logger.info(f"异常分数范围: [{anomaly_scores.min():.2f}, {anomaly_scores.max():.2f}]")
        
        # 8. 找出top异常
        if anomaly_count > 0:
            # 计算标准化的异常分数
            normalized_scores = 100 * (1 - (anomaly_scores - anomaly_scores.min()) / (anomaly_scores.max() - anomaly_scores.min() + 1e-10))
            
            # 创建包含异常标记和分数的数据副本
            anomaly_df = data.copy()
            anomaly_df['anomaly'] = anomalies
            anomaly_df['anomaly_score'] = normalized_scores
            
            # 选择异常样本并按分数排序
            anomaly_records = anomaly_df[anomaly_df['anomaly']].sort_values('anomaly_score', ascending=False)
            
            # 打印前5个异常样本
            logger.info("\nTop 5异常样本:")
            for i, (_, row) in enumerate(anomaly_records.head(5).iterrows()):
                anomaly_info = {
                    "ip": row['src_ip'] if 'src_ip' in row else 'unknown',
                    "threat_level": row['threat_level'] if 'threat_level' in row else 'unknown',
                    "anomaly_score": row['anomaly_score'],
                    "signature": row['signature'] if 'signature' in row else 'unknown'
                }
                logger.info(f"异常 {i+1}: {anomaly_info}")
                
        logger.info("完整流水线测试成功")
    except Exception as e:
        logger.error(f"完整流水线测试失败: {str(e)}")
        logger.error(traceback.format_exc())

def create_mock_data():
    """创建模拟数据以测试模型初始化"""
    logger.info("创建模拟测试数据")
    
    # 创建模拟数据
    n_samples = 100
    data = {
        'event_time': [datetime.now() - timedelta(hours=i) for i in range(n_samples)],
        'src_ip': [f'192.168.1.{i % 255}' for i in range(n_samples)],
        'dst_ip': [f'10.0.0.{i % 255}' for i in range(n_samples)],
        'threat_level': np.random.randint(10, 50, n_samples),
        'src_port': np.random.randint(1024, 65535, n_samples),
        'dst_port': np.random.randint(1, 1024, n_samples),
        'signature': [f'测试签名-{i % 10}' for i in range(n_samples)],
        'network_type': ['测试网络' for _ in range(n_samples)],
        'ip_type': ['internal' for _ in range(n_samples)]
    }
    
    # 将部分IP标记为外部
    for i in range(n_samples):
        if i % 10 == 0:  # 10%的IP为外部
            data['ip_type'][i] = 'external'
            data['src_ip'][i] = f'8.8.8.{i % 255}'  # 外部IP
    
    # 创建DataFrame
    df = pd.DataFrame(data)
    logger.info(f"成功创建{len(df)}条模拟数据")
    
    return df

def main():
    """主函数"""
    logger.info("开始测试模型初始化问题")
    
    # 检查数据库表
    logger.info("检查数据库表结构")
    check_database_tables()
    
    # 测试简单查询
    logger.info("测试简单数据库查询")
    test_simple_query()
    
    # 获取测试数据
    hours = 24  # 使用最近24小时的数据
    logger.info(f"获取最近{hours}小时的数据")
    data = fetch_data(hours)
    
    # 如果无法获取真实数据，使用模拟数据
    if data.empty:
        logger.warning("无法获取数据库数据，使用模拟数据代替")
        data = create_mock_data()
    
    if data.empty:
        logger.error("无法获取数据，测试结束")
        return
    
    # 测试StandardScaler
    test_standard_scaler(data)
    
    # 测试IsolationForest
    test_isolation_forest(data)
    
    # 测试完整流水线
    test_full_pipeline(data)
    
    logger.info("测试完成")

if __name__ == "__main__":
    main() 