"""
测试安全查询API
"""
import requests
import json
import time
import sys

# API请求URL
url = "http://localhost:8000/api/v1/query"

# 请求头
headers = {
    "Content-Type": "application/json"
}

# 测试查询示例
test_queries = [
    # {
    #     "title": "基本高风险查询",
    #     "payload": {
    #         "question": "查询最近一周威胁等级大于30的高危报警，分析其中的安全风险",
    #         "use_ml": True
    #     }
    # },
    # {
    #     "title": "内外部IP对比分析",
    #     "payload": {
    #         "question": "分析最近7天来自外部IP的安全事件与内部IP的差异",
    #         "use_ml": True
    #     }
    # },
    {
        "title": "完整安全分析",
        "payload": {
            "question": "分析最近一周的网络攻击，重点关注高风险攻击，重点关注外部IP，评估风险等级",
            "use_ml": True
        }
    }
]

def test_query_api(query_index=0):
    """测试查询API"""
    if query_index >= len(test_queries):
        print("没有更多测试查询")
        return
        
    test_case = test_queries[query_index]
    print(f"\n测试 #{query_index+1}: {test_case['title']}")
    print("-" * 80)
    print(f"问题: {test_case['payload']['question']}")
    print(f"使用机器学习: {test_case['payload']['use_ml']}")
    print("-" * 80)
    
    try:
        # 发送POST请求
        response = requests.post(
            url, 
            json=test_case['payload'], 
            headers=headers
        )
        
        # 检查响应状态码
        print(f"响应状态码: {response.status_code}")
        
        # 如果成功，打印响应内容
        if response.status_code == 200:
            result = response.json()
            
            # 打印SQL查询和结果概要
            print("\n生成的SQL查询:")
            print("-" * 80)
            print(result["sql_query"])
            print("-" * 80)
            
            # 显示结果长度
            result_length = len(result["sql_result"]) if "sql_result" in result else 0
            print(f"\nSQL查询结果长度: {result_length} 字符")
            
            # 打印SQL查询结果的前200个字符（仅供调试）
            if result_length > 0:
                print("\nSQL查询结果前200个字符:")
                print("-" * 80)
                print(result["sql_result"][:200] + "..." if result_length > 200 else result["sql_result"])
                print("-" * 80)
            
            # 打印完整的安全分析结果（调试用）
            print("\n安全分析结果原始数据:")
            print("-" * 80)
            print(json.dumps(result["security_analysis"], ensure_ascii=False, indent=2))
            print("-" * 80)
            
            # 打印安全分析
            print("\n安全分析结果:")
            print("=" * 80)
            print(result["formatted_answer"])
            print("=" * 80)
            
            # 检查是否包含内外部IP区分
            security_analysis = result.get("security_analysis", {})
            ip_analysis = security_analysis.get("ip_analysis", "")
            
            if "内部IP" in ip_analysis and "外部IP" in ip_analysis:
                print("\n✅ 成功区分了内部和外部IP")
            
            # 打印机器学习分析结果详情
            print("\n机器学习分析结果详情:")
            print("=" * 80)
            
            if "ml_analysis" in security_analysis:
                print("✅ 包含机器学习分析结果")
                print("-" * 80)
                print(security_analysis["ml_analysis"])
                print("-" * 80)
                
                # 提取并打印风险评分详情
                print("\n🔍 机器学习风险评分详情:")
                print("-" * 80)
                
                ml_text = security_analysis["ml_analysis"]
                
                # 检查是否存在外部IP警告
                has_external_ip_warning = "外部IP警告" in ml_text or "检测到" in ml_text and "外部" in ml_text and "IP" in ml_text
                
                if has_external_ip_warning:
                    print("【⚠️ 外部IP警告】")
                    external_ip_warning = ml_text.split("⚠️ 外部IP警告:")[1].split("\n\n")[0].strip() if "⚠️ 外部IP警告:" in ml_text else "检测到外部IP"
                    print(f"  {external_ip_warning}")
                    print("  根据新的风险评级策略，任何包含外部IP的攻击都被视为高风险(100分)")
                    print("  外部IP的得分贡献: 100/100 分")
                
                # 解析异常检测部分
                if "异常检测:" in ml_text:
                    anomaly_part = ml_text.split("异常检测:")[1].split(".")[0].strip()
                    print(f"【异常检测得分(30%)】: {anomaly_part}")
                    
                    # 尝试提取异常记录数和分数
                    import re
                    anomaly_count_match = re.search(r'发现(\d+)条异常记录', anomaly_part)
                    anomaly_score_match = re.search(r'平均异常分数(\d+\.?\d*)', anomaly_part)
                    
                    if anomaly_count_match and anomaly_score_match:
                        count = int(anomaly_count_match.group(1))
                        score = float(anomaly_score_match.group(1))
                        
                        # 根据ML模型中的计算方式估算分数
                        anomaly_percentage = min(count / 10, 1.0) if count > 0 else 0
                        score_factor = min(score / 100, 1.0)
                        estimated_score = 30 * anomaly_percentage * score_factor
                        
                        print(f"  - 异常记录数: {count}")
                        print(f"  - 平均异常分数: {score}")
                        print(f"  - 估算得分贡献: {estimated_score:.1f}/30 分")
                
                # 解析IP信誉部分
                if "IP分析:" in ml_text:
                    ip_part = ml_text.split("IP分析:")[1]
                    if "攻击预测:" in ip_part:
                        ip_part = ip_part.split("攻击预测:")[0].strip()
                    else:
                        ip_part = ip_part.strip()
                    
                    print(f"【IP信誉得分(40%)】: {ip_part}")
                    
                    # 提取外部可疑IP数量
                    suspicious_match = re.search(r'发现(\d+)个可疑外部IP', ml_text)
                    if suspicious_match:
                        suspicious_count = int(suspicious_match.group(1))
                        
                        # 根据ML模型中的计算方式估算分数
                        ip_factor = min(suspicious_count * 2 / 6, 1.0)  # 假设全部是外部IP，权重2.0
                        estimated_score = 40 * ip_factor
                        
                        print(f"  - 可疑外部IP数: {suspicious_count}")
                        print(f"  - 估算得分贡献: {estimated_score:.1f}/40 分")
                
                # 解析攻击预测部分
                if "攻击预测:" in ml_text:
                    attack_part = ml_text.split("攻击预测:")[1].strip()
                    print(f"【攻击预测得分(30%)】: {attack_part}")
                    
                    # 提取攻击概率
                    probability_match = re.search(r'攻击概率为(\d+\.?\d*)%', attack_part)
                    if probability_match:
                        probability = float(probability_match.group(1))
                        
                        # 根据ML模型中的计算方式估算分数
                        estimated_score = 30 if probability > 70 else 0
                        
                        print(f"  - 最高攻击概率: {probability}%")
                        print(f"  - 估算得分贡献: {estimated_score}/30 分")
                
                # 总风险分数估算
                print("\n📊 总风险分数估算:")
                risk_level = security_analysis.get("risk_level", "未知")
                print(f"  - 当前风险等级: {risk_level}")
                
                # 更新风险等级判断标准展示，包括外部IP情况
                print(f"  - 风险等级判断标准:")
                print(f"    * 存在外部IP: 自动判定为高风险")
                print(f"    * 总分 > 60: 高风险")
                print(f"    * 总分 > 30: 中风险")
                print(f"    * 总分 ≤ 30: 低风险")
                
                # 如果存在外部IP，显示外部IP自动导致高风险的说明
                if has_external_ip_warning:
                    print(f"\n  ⚠️ 由于检测到外部IP，系统自动将风险等级评为'高'")
            else:
                print("❌ 未找到机器学习分析结果")
                print("可能的原因:")
                print("1. 模型文件不存在或未正确加载")
                print("2. 机器学习链未正确初始化")
                print("3. API请求中的use_ml参数未生效")
                print("\n在security_analysis对象中找到的键:")
                print(", ".join(security_analysis.keys()))
        else:
            print(f"请求失败: {response.text}")
    
    except Exception as e:
        print(f"发生错误: {e}")
        import traceback
        print(traceback.format_exc())

if __name__ == "__main__":
    # 等待服务器启动
    print("等待服务器启动...")
    time.sleep(3)
    
    # 测试所有查询
    for i in range(len(test_queries)):
        test_query_api(i)
        # 每次查询之间等待一些时间
        if i < len(test_queries) - 1:
            print("\n等待5秒进行下一次查询...")
            time.sleep(5) 