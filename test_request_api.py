import requests
import json
import time

def test_api_request(question, use_ml=True, check_sql_result=False):
    # API endpoint
    url = "http://localhost:8000/api/v1/query"
    
    # 准备请求数据
    payload = {
        "question": question,
        "use_ml": use_ml,
        "database_name": "itm"
    }
    
    print(f"发送请求到: {url}")
    print(f"请求数据: {json.dumps(payload, indent=2, ensure_ascii=False)}")
    print("-" * 80)
    
    # 发送POST请求
    try:
        response = requests.post(url, json=payload)
        
        print(f"响应状态码: {response.status_code}")
        
        # 检查状态码
        if response.status_code == 200:
            print("请求成功！")
            
            # 解析JSON响应
            try:
                data = response.json()
                print(f"响应大小: {len(response.text)} bytes")
                
                # 打印SQL查询
                print("\n生成的SQL查询:")
                print("-" * 80)
                print(data.get('sql_query', 'N/A'))
                print("-" * 80)
                
                # 检查SQL结果格式
                if 'sql_result' in data:
                    result_length = len(data['sql_result'])
                    print(f"\nSQL查询结果长度: {result_length} 字符")
                    
                    # 打印SQL查询结果的前200个字符
                    print("\nSQL查询结果前200个字符:")
                    print("-" * 80)
                    print(data['sql_result'][:200] + "..." if result_length > 200 else data['sql_result'])
                    print("-" * 80)
                    
                    # 检查结果是否为JSON字符串
                    try:
                        if isinstance(data['sql_result'], str):
                            json_obj = json.loads(data['sql_result'])
                            print(f"SQL结果可以解析为JSON，包含{len(json_obj)}条记录")
                    except:
                        print("SQL结果不是有效的JSON格式")
                
                # 打印安全分析结果原始数据
                if "security_analysis" in data:
                    print("\n安全分析结果原始数据:")
                    print("-" * 80)
                    print(json.dumps(data["security_analysis"], ensure_ascii=False, indent=2))
                    print("-" * 80)
                    
                    # 打印安全分析
                    print("\n安全分析结果:")
                    print("=" * 80)
                    print(data.get("formatted_answer", "未提供格式化回答"))
                    print("=" * 80)
                    
                    # 检查IP分析
                    ip_analysis = data["security_analysis"].get("ip_analysis", "")
                    if "内部IP" in ip_analysis and "外部IP" in ip_analysis:
                        print("\n✅ 成功区分了内部和外部IP")
                    
                    # 检查是否有机器学习分析
                    print("\n机器学习分析结果详情:")
                    print("=" * 80)
                    
                    if "ml_analysis" in data["security_analysis"]:
                        print("✅ 包含机器学习分析结果")
                        print("-" * 80)
                        print(data["security_analysis"]["ml_analysis"])
                        print("-" * 80)
                        
                        # 获取ML分析详情
                        ml_text = data["security_analysis"]["ml_analysis"]
                        
                        # 解析异常检测部分
                        if "异常检测:" in ml_text:
                            anomaly_part = ml_text.split("异常检测:")[1].split(".")[0].strip()
                            print(f"\n【异常检测】: {anomaly_part}")
                            
                        # 解析IP信誉部分
                        if "IP分析:" in ml_text:
                            ip_part = ml_text.split("IP分析:")[1]
                            if "攻击预测:" in ip_part:
                                ip_part = ip_part.split("攻击预测:")[0].strip()
                            else:
                                ip_part = ip_part.strip()
                            
                            print(f"\n【IP信誉分析】: {ip_part}")
                            
                        # 解析攻击预测部分
                        if "攻击预测:" in ml_text:
                            attack_part = ml_text.split("攻击预测:")[1].strip()
                            print(f"\n【攻击预测】: {attack_part}")
                    else:
                        print("❌ 未找到机器学习分析结果")
                        print("可能的原因:")
                        print("1. 模型文件不存在或未正确加载")
                        print("2. 机器学习链未正确初始化")
                        print("3. API请求中的use_ml参数未生效")
                        print("\n在security_analysis对象中找到的键:")
                        print(", ".join(data["security_analysis"].keys()))
                        
                        # 检查是否有机器学习错误
                        if "ml_error" in data["security_analysis"]:
                            print(f"\n机器学习错误:")
                            print(data["security_analysis"]["ml_error"])
                
                return data
                
            except json.JSONDecodeError as e:
                print(f"解析JSON响应失败: {e}")
                print("原始响应内容:")
                print(response.text[:1000])
        else:
            print(f"请求失败，状态码: {response.status_code}")
            print("响应内容:")
            print(response.text[:1000])
            
    except requests.exceptions.RequestException as e:
        print(f"请求发生错误: {e}")
        
    return None

# 测试健康检查API
def test_health_endpoint():
    print("\n===== 测试健康检查 =====")
    url = "http://localhost:8000/health"
    
    try:
        response = requests.get(url)
        print(f"状态码: {response.status_code}")
        
        if response.status_code == 200:
            print("健康检查成功!")
            print(f"响应内容: {response.text}")
        else:
            print(f"健康检查失败，状态码: {response.status_code}")
            print(f"响应内容: {response.text}")
            
    except requests.exceptions.RequestException as e:
        print(f"健康检查请求错误: {e}")

# 主程序
if __name__ == "__main__":
    # 等待服务器启动
    print("等待服务器启动...")
    time.sleep(2)
    
    # 测试1：使用完整安全分析问题
    print("\n===== 测试1: 完整安全分析 =====")
    question1 = "分析最近出现的攻击类型和攻击源IP，重点关注外部IP，评估风险等级"
    print(f"问题: {question1}")
    print(f"使用机器学习: True")
    print("-" * 80)
    response1 = test_api_request(question1, use_ml=True, check_sql_result=True)
    
    # # 等待5秒
    # print("\n等待5秒进行下一次查询...")
    # time.sleep(5)
    
    # # 测试2：基本高风险查询
    # print("\n===== 测试2: 基本高风险查询 =====")
    # question2 = "查询最近一周威胁等级大于30的高危报警，分析其中的安全风险"
    # print(f"问题: {question2}")
    # print(f"使用机器学习: True")
    # print("-" * 80)
    # response2 = test_api_request(question2, use_ml=True, check_sql_result=True)
    
    # 测试健康检查
    test_health_endpoint()
    
    print("\n测试完成")