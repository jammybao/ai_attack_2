'''
Description: 
version: 
Author: Bao Jiaming
Date: 2025-03-24 06:15:54
LastEditTime: 2025-03-24 06:17:43
FilePath: \test_ml_chain.py
'''
"""
测试机器学习安全链的脚本
"""
import os
import pandas as pd
import json
from security_agent.chains.ml_security_chain import MLSecurityChain

def test_ml_security_chain():
    print("开始测试机器学习安全链...")
    
    # 设置模型路径
    models_dir = "./models"
    anomaly_model_path = os.path.join(models_dir, "anomaly_model.pkl")
    ip_reputation_model_path = os.path.join(models_dir, "ip_reputation_model.pkl")
    attack_chain_model_path = os.path.join(models_dir, "attack_chain_model.pkl")
    
    # 检查模型文件是否存在
    print(f"检查模型文件:")
    print(f"- 异常检测模型文件是否存在: {os.path.exists(anomaly_model_path)}")
    print(f"- IP信誉模型文件是否存在: {os.path.exists(ip_reputation_model_path)}")
    print(f"- 攻击链预测模型文件是否存在: {os.path.exists(attack_chain_model_path)}")
    
    # 初始化ML安全链
    print("\n初始化机器学习安全链...")
    ml_chain = MLSecurityChain(
        anomaly_model_path=anomaly_model_path,
        ip_reputation_model_path=ip_reputation_model_path,
        attack_chain_model_path=attack_chain_model_path
    )
    
    # 检查模型是否已加载
    print(f"异常检测模型是否已加载: {ml_chain.anomaly_model is not None}")
    print(f"攻击链预测模型是否已加载: {ml_chain.attack_chain_model is not None}")
    print(f"IP信誉模型是否已加载: {ml_chain.ip_reputation_model is not None}")
    
    if ml_chain.anomaly_model:
        print(f"异常检测模型内部模型是否存在: {ml_chain.anomaly_model.model is not None}")
    if ml_chain.attack_chain_model:
        print(f"攻击链预测模型内部模型是否存在: {ml_chain.attack_chain_model.model is not None}")
    
    # 准备模拟的SQL结果数据
    print("\n准备模拟数据进行测试...")
    test_data = """
    [
        {"event_time":"2025-03-01 12:34:56","event_type":"入侵检测","device_name":"FW-01","src_ip":"192.168.1.10","threat_level":"高","category":"攻击利用","attack_function":"命令执行","attack_step":"漏洞利用","signature":"SQL注入攻击","dst_ip":"10.0.0.5","protocol":"TCP","src_port":12345,"dst_port":80,"bytes_sent":1024,"bytes_received":2048},
        {"event_time":"2025-03-01 12:35:56","event_type":"入侵检测","device_name":"FW-01","src_ip":"8.8.8.8","threat_level":"高","category":"攻击利用","attack_function":"命令执行","attack_step":"漏洞利用","signature":"命令注入攻击","dst_ip":"10.0.0.5","protocol":"TCP","src_port":33445,"dst_port":80,"bytes_sent":2048,"bytes_received":4096},
        {"event_time":"2025-03-01 12:36:56","event_type":"入侵检测","device_name":"IDS-02","src_ip":"192.168.1.20","threat_level":"中","category":"可疑行为","attack_function":"信息收集","attack_step":"扫描","signature":"端口扫描","dst_ip":"10.0.0.10","protocol":"TCP","src_port":45678,"dst_port":0,"bytes_sent":512,"bytes_received":128}
    ]
    """
    
    # 测试数据预处理
    print("\n测试数据预处理...")
    try:
        data = ml_chain.preprocess_data(test_data)
        print(f"预处理结果: {'成功' if not data.empty else '失败'}")
        print(f"预处理后数据行数: {len(data)}")
        print(f"预处理后数据列: {list(data.columns) if not data.empty else '无数据'}")
        
        if not data.empty:
            print("\n预处理后数据前3行:")
            print(data.head(3).to_string())
    except Exception as e:
        import traceback
        print(f"数据预处理错误: {e}")
        print(traceback.format_exc())
    
    # 测试机器学习增强安全分析
    print("\n测试机器学习增强安全分析...")
    # 准备原始分析结果
    original_analysis = {
        "risk_level": "中",
        "key_findings": ["发现可疑的外部IP连接"],
        "recommendations": ["检查外部连接的合法性"],
        "ip_analysis": "发现3个IP地址，其中包括2个内部IP和1个外部IP。"
    }
    
    try:
        # 测试预处理直接解析JSON字符串的形式
        print("\n测试JSON解析预处理...")
        try:
            records = json.loads(test_data)
            print(f"JSON解析成功，包含{len(records)}条记录")
        except Exception as je:
            print(f"JSON解析错误: {je}")
            
        # 调用增强分析方法
        enhanced_result = ml_chain.enhance_security_analysis(
            sql_result=test_data,
            original_analysis=original_analysis
        )
        
        # 检查结果
        print("\n增强分析结果:")
        print(f"风险等级: {enhanced_result.get('risk_level', '未知')}")
        
        if "key_findings" in enhanced_result:
            print("\n关键发现:")
            for finding in enhanced_result["key_findings"]:
                print(f"- {finding}")
        
        if "recommendations" in enhanced_result:
            print("\n建议:")
            for rec in enhanced_result["recommendations"]:
                print(f"- {rec}")
        
        if "ml_analysis" in enhanced_result:
            print("\n机器学习分析:")
            print(enhanced_result["ml_analysis"])
        else:
            print("\n没有机器学习分析结果")
            
        if "ml_error" in enhanced_result:
            print("\n机器学习错误:")
            print(enhanced_result["ml_error"])
            
    except Exception as e:
        import traceback
        print(f"测试过程中发生错误: {e}")
        print(traceback.format_exc())
    
    print("\n测试完成")

if __name__ == "__main__":
    test_ml_security_chain() 