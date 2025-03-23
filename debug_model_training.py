"""
调试模型训练功能，输出更多调试信息
"""
import requests
import json
import time
import os
import pandas as pd
import numpy as np
from pathlib import Path
import traceback

# API请求URL
url = "http://localhost:8000/api/v1/ml/train"

def debug_model_training():
    """调试模型训练API"""
    print("开始调试模型训练API...")
    
    try:
        from sqlalchemy import create_engine, text
        from security_agent.config import settings
        
        # 创建数据库引擎
        engine = create_engine(settings.DB_CONNECTION_STRING)
        print(f"成功连接到数据库: {settings.DB_CONNECTION_STRING}")
        
        # 查询训练数据
        with engine.connect() as conn:
            query = """
            SELECT 
                event_time, event_type, device_name, src_ip, threat_level, 
                category, attack_function, attack_step, signature, dst_ip, protocol,
                src_port, dst_port, bytes_to_server as bytes_sent, bytes_to_client as bytes_received
            FROM ids_ai
            LIMIT 1000
            """
            result = conn.execute(text(query))
            df = pd.DataFrame(result.fetchall(), columns=result.keys())
            
        print(f"获取到{len(df)}条训练数据")
        print(f"数据列名: {list(df.columns)}")
        print(f"attack_step列值分布: {df['attack_step'].value_counts()}")
        print(f"数值列: {df.select_dtypes(include=['number']).columns.tolist()}")
        
        # 保存为CSV
        csv_path = 'debug_training_data.csv'
        df.to_csv(csv_path, index=False)
        print(f"训练数据已保存到 {csv_path}")
        
        # 确保有多个不同的攻击步骤值
        unique_steps = df['attack_step'].unique()
        if len(unique_steps) <= 1:
            print(f"警告：attack_step列只有{len(unique_steps)}个不同值，增加一些模拟数据")
            # 添加一些模拟数据，确保有多个不同的攻击步骤值
            new_rows = df.iloc[:20].copy()
            new_rows['attack_step'] = '数据窃取'  # 添加不同的攻击步骤
            df = pd.concat([df, new_rows], ignore_index=True)
            
            new_rows = df.iloc[:20].copy()
            new_rows['attack_step'] = '横向移动'  # 添加不同的攻击步骤
            df = pd.concat([df, new_rows], ignore_index=True)
            
            df.to_csv(csv_path, index=False)
            print(f"增加模拟数据后的attack_step列值分布: {df['attack_step'].value_counts()}")
        
        # 选择数值列作为异常检测特征
        numeric_columns = df.select_dtypes(include=['number']).columns.tolist()
        
        # 将类别型特征转换为可用于模型的格式
        df_for_model = df.copy()
        categorical_features = ['category', 'attack_function', 'attack_step']
        
        for feature in categorical_features:
            if feature in df.columns:
                # 检查列是否为空
                if df[feature].isna().sum() > 0:
                    print(f"警告：{feature}列包含{df[feature].isna().sum()}个空值")
                    df_for_model[feature] = df_for_model[feature].fillna('未知')
                
                # 对每个分类特征进行简单的整数编码
                df_for_model[feature + '_encoded'] = pd.factorize(df_for_model[feature])[0]
        
        # 修改要使用的攻击特征，包括编码后的特征
        attack_features = numeric_columns + [f + '_encoded' for f in categorical_features if f + '_encoded' in df_for_model.columns]
        print(f"用于训练的特征: {attack_features}")
        
        # 修改CSV
        enhanced_csv_path = 'enhanced_training_data.csv'
        df_for_model.to_csv(enhanced_csv_path, index=False)
        print(f"增强的训练数据已保存到 {enhanced_csv_path}")
        
        # 发送训练请求
        print("\n发送模型训练请求...")
        with open(enhanced_csv_path, 'rb') as f:
            files = {'file': (os.path.basename(enhanced_csv_path), f, 'text/csv')}
            
            # 使用编码后的目标字段
            form_data = {
                "anomaly_features": json.dumps(numeric_columns),
                "attack_features": json.dumps(attack_features),
                "attack_target": "attack_step_encoded"  # 使用编码后的字段
            }
            
            print(f"请求参数: {form_data}")
            
            response = requests.post(
                url, 
                files=files,
                data=form_data
            )
        
        # 检查响应
        print(f"响应状态码: {response.status_code}")
        
        if response.status_code == 200:
            result = response.json()
            print("\n训练结果:")
            print(json.dumps(result, ensure_ascii=False, indent=2))
            
            if result.get("success"):
                print("\n✅ 模型训练成功!")
                
                # 检查模型文件
                models_dir = Path('./models')
                print(f"模型目录内容: {list(models_dir.glob('*.pkl'))}")
            else:
                print("\n❌ 模型训练失败!")
        else:
            print(f"请求失败: {response.text}")
            
    except Exception as e:
        print(f"模型训练调试过程中发生错误: {e}")
        print(traceback.format_exc())
        
if __name__ == "__main__":
    # 等待服务器启动
    print("等待服务器启动...")
    time.sleep(2)
    
    # 调试模型训练
    debug_model_training() 