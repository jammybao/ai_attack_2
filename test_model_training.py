"""
测试模型训练功能
"""
import requests
import json
import time
import os
import pandas as pd
from pathlib import Path

# API请求URL
url = "http://localhost:8000/api/v1/ml/train"

def test_model_training():
    """测试模型训练API"""
    print("开始测试模型训练API...")
    
    # 1. 首先从数据库获取一些数据用于训练
    print("从数据库获取训练数据...")
    
    try:
        from sqlalchemy import create_engine, text
        from security_agent.config import settings
        
        # 创建数据库引擎
        engine = create_engine(settings.DB_CONNECTION_STRING)
        print(f"成功连接到数据库: {settings.DB_CONNECTION_STRING}")
        
        # 查询训练数据 - 修改为匹配实际表结构，获取最近30天的数据
        with engine.connect() as conn:
            query = """
            SELECT 
                event_time, event_type, device_name, src_ip, threat_level, 
                category, attack_function, attack_step, signature, dst_ip, protocol,
                src_port, dst_port, bytes_to_server as bytes_sent, bytes_to_client as bytes_received
            FROM ids_ai
            WHERE event_time >= CURDATE() - INTERVAL 30 DAY
            ORDER BY event_time
            """
            result = conn.execute(text(query))
            df = pd.DataFrame(result.fetchall(), columns=result.keys())
            
        print(f"获取到{len(df)}条训练数据")
        
        # 保存为CSV
        csv_path = 'training_data.csv'
        df.to_csv(csv_path, index=False)
        print(f"训练数据已保存到 {csv_path}")
        
        # 打印一些数据统计信息
        print(f"数据列名: {list(df.columns)}")
        print(f"数值列: {df.select_dtypes(include=['number']).columns.tolist()}")
        print(f"attack_function列值分布: {df['attack_function'].value_counts().head()}")
        print(f"attack_step列值分布: {df['attack_step'].value_counts().head()}")
        
        # 2. 准备训练请求
        # 选择数值列作为异常检测特征
        numeric_columns = df.select_dtypes(include=['number']).columns.tolist()
        
        # 添加其他重要的特征 - 对分类特征进行编码
        # 在测试脚本中我们不需要实际进行编码，因为API会处理
        important_categorical = ['category', 'attack_function', 'signature']
        
        # 3. 发送训练请求
        print("\n发送模型训练请求...")
        
        # 修改请求发送方式
        with open(csv_path, 'rb') as f:
            files = {'file': (os.path.basename(csv_path), f, 'text/csv')}
            
            # 直接在请求表单中添加参数，更新为使用attack_function作为目标
            form_data = {
                "anomaly_features": json.dumps(numeric_columns),
                # API会自动处理特征，不需要在客户端指定
                "attack_features": json.dumps([]),  
                # 使用attack_function作为目标而不是attack_step
                "attack_target": "attack_function_encoded"
            }
            
            response = requests.post(
                url, 
                files=files,
                data=form_data
            )
        
        # 4. 检查响应
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
        print(f"模型训练过程中发生错误: {e}")
        import traceback
        print(traceback.format_exc())
        
if __name__ == "__main__":
    # 等待服务器启动
    print("等待服务器启动...")
    time.sleep(3)
    
    # 测试模型训练
    test_model_training() 