"""
使用curl直接调用API测试
"""
import subprocess
import json
import time
import os

def run_curl_query(question, use_ml=True):
    # 准备payload
    payload = {
        "question": question,
        "use_ml": use_ml,
        "database_name": "itm"
    }
    
    # 构建curl命令
    curl_cmd = f'curl -v -X POST -H "Content-Type: application/json" -d \'{json.dumps(payload)}\' http://localhost:8000/api/v1/query'
    
    print(f"执行命令: {curl_cmd}")
    print(f"Payload数据: {json.dumps(payload, indent=2, ensure_ascii=False)}")
    
    # 执行curl命令
    try:
        result = subprocess.run(curl_cmd, shell=True, capture_output=True, text=True)
        print(f"API返回状态码: {result.returncode}")
        
        print("===== STDOUT 输出内容 =====")
        print(result.stdout[:1000])
        
        print("===== STDERR 输出内容 =====")
        print(result.stderr[:1000])
            
        # 尝试解析JSON响应
        try:
            response = json.loads(result.stdout)
            print(f"成功获取API响应，响应长度: {len(result.stdout)}")
            
            # 检查安全分析部分
            if "security_analysis" in response:
                print("安全分析结果包含以下键:")
                for key in response["security_analysis"].keys():
                    print(f"  - {key}")
                
                # 检查是否有机器学习分析结果
                if "ml_analysis" in response["security_analysis"]:
                    print(f"机器学习分析结果: {response['security_analysis']['ml_analysis']}")
                else:
                    print("未找到机器学习分析结果")
                    
                # 检查是否有ml_error
                if "ml_error" in response["security_analysis"]:
                    print(f"机器学习错误: {response['security_analysis']['ml_error']}")
                    
                # 检查风险级别
                print(f"风险级别: {response['security_analysis'].get('risk_level', '未知')}")
                
            else:
                print("响应中没有security_analysis部分")
                
            return response
            
        except json.JSONDecodeError as e:
            print(f"解析JSON失败: {e}")
            print(f"原始响应不是JSON格式")
            return None
            
    except Exception as e:
        print(f"执行curl命令失败: {e}")
        return None

# 测试1：启用机器学习
print("\n\n===== 测试1: 启用机器学习 =====")
question1 = "帮我分析最近的攻击类型及来源IP，使用机器学习进行综合安全分析"
response1 = run_curl_query(question1, use_ml=True)

# 等待2秒
time.sleep(2)

# 测试服务健康状态
print("\n\n===== 测试健康检查 =====")
health_cmd = "curl -v http://localhost:8000/health"
print(f"执行命令: {health_cmd}")
health_result = subprocess.run(health_cmd, shell=True, capture_output=True, text=True)
print(f"状态码: {health_result.returncode}")
print("标准输出:")
print(health_result.stdout)
print("错误输出:")
print(health_result.stderr)

print("\n测试完成") 