'''
Description: 测试TimeRangeParserChain类的功能
Author: 
Date: 2025-03-04
'''
import asyncio
import os
import sys

# # 添加项目根目录到Python路径
# sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
from security_agent.config import settings
from security_agent.chains.time_parser_chain import TimeRangeParserChain

async def test_time_range_parser():
    # 从环境变量获取API密钥，或者直接在这里设置
    api_key = settings.TONGYI_API_KEY
     # 打印API密钥的前5个和后5个字符，中间用星号代替（安全考虑）
    if api_key and len(api_key) > 10:
        masked_key = api_key[:5] + "*" * (len(api_key) - 10) + api_key[-5:]
    else:
        masked_key = api_key
    
    print(f"\n实际使用的API密钥: {masked_key}")
    print(f"API密钥长度: {len(api_key)}")
    
    # 初始化解析器
    parser = TimeRangeParserChain(
        api_key=api_key,
        model_name="qwen-plus",
        base_url="https://dashscope.aliyuncs.com/compatible-mode/v1"
    )
    
    # 测试用例
    test_queries = [
        "分析过去24小时的数据",
        "查看昨天的报表",
        "统计上周一到上周五的销售情况",
        "本月初至今的用户增长",
        "前天下午3点到昨天晚上8点的系统日志",
        "没有明确时间范围的查询"
    ]
    
    # 测试每个查询
    for query in test_queries:
        print(f"\n测试查询: '{query}'")
        try:
            result = await parser.parse_time_range(query)
            print(f"解析结果:")
            print(f"  起始时间: {result['start_time']}")
            print(f"  结束时间: {result['end_time']}")
            print(f"  描述: {result['description']}")
            if 'formatted_range' in result:
                print(f"  格式化范围: {result['formatted_range']}")
            if 'error' in result:
                print(f"  错误: {result['error']}")
        except Exception as e:
            print(f"解析失败: {str(e)}")

async def main():
    print("开始测试 TimeRangeParserChain...")
    await test_time_range_parser()
    print("\n测试完成!")

if __name__ == "__main__":
    # 运行异步主函数
    asyncio.run(main()) 