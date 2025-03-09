"""
官方SQL查询链集成测试 - 直接对接项目数据库环境
"""
import os
import sys
import unittest
import logging
import json
from datetime import datetime, timedelta
from dotenv import load_dotenv

# 添加项目根目录到路径
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

# 加载环境变量
load_dotenv()

from security_agent.chains.official_sql_chain import OfficialSQLChain
from security_agent.config import settings

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class TestOfficialSQLChainIntegration(unittest.TestCase):
    """官方SQL查询链集成测试"""
    
    @classmethod
    def setUpClass(cls):
        """测试类初始化"""
        logger.info("初始化官方SQL查询链集成测试")
        
        # 创建官方SQL查询链实例
        cls.sql_chain = OfficialSQLChain(
            api_key=settings.TONGYI_API_KEY,
            db_connection=settings.DB_CONNECTION_STRING,
            model_name=settings.TONGYI_MODEL_NAME,
            base_url=settings.TONGYI_BASE_URL
        )
        
        # 获取可用表名
        cls.table_names = cls.sql_chain.get_usable_table_names()
        logger.info(f"可用表名: {cls.table_names}")
        
        # 确保ids_ai表存在
        if 'ids_ai' not in cls.table_names:
            logger.warning("ids_ai表不存在，测试可能会失败")
    
    def format_result(self, result):
        """格式化查询结果，尝试转换为JSON"""
        try:
            # 尝试解析为JSON
            parsed_result = json.loads(result)
            return json.dumps(parsed_result, indent=2, ensure_ascii=False)
        except:
            # 尝试解析为Python对象
            try:
                import ast
                parsed_result = ast.literal_eval(result)
                if isinstance(parsed_result, list):
                    # 尝试推断列名
                    if len(parsed_result) > 0 and isinstance(parsed_result[0], tuple):
                        # 从查询中提取列名
                        columns = self.sql_chain._extract_columns_from_query(self.current_sql)
                        if not columns:
                            columns = [f"column_{i}" for i in range(len(parsed_result[0]))]
                        
                        # 转换为字典列表
                        dict_result = []
                        for row in parsed_result:
                            dict_row = {}
                            for i, value in enumerate(row):
                                if i < len(columns):
                                    dict_row[columns[i]] = value
                                else:
                                    dict_row[f"column_{i}"] = value
                            dict_result.append(dict_row)
                        return json.dumps(dict_result, indent=2, ensure_ascii=False)
                return str(parsed_result)
            except:
                # 如果都失败，返回原始结果
                return result
    
    def test_get_table_info(self):
        """测试获取表信息"""
        logger.info("\n\n==== 测试获取表信息 ====")
        
        # 获取ids_ai表信息
        table_info = self.sql_chain.get_table_info(['ids_ai'])
        
        # 验证表信息不为空
        self.assertIsNotNone(table_info)
        self.assertIn('ids_ai', table_info)
        
        # 打印表信息（限制长度）
        print("\n表信息:")
        print("=" * 80)
        print(table_info[:1000] + "..." if len(table_info) > 1000 else table_info)
        print("=" * 80)
    
    # def test_recent_high_threat_events(self):
    #     """测试用例1: 查询最近24小时内高威胁等级的事件"""
    #     logger.info("\n\n==== 测试用例1: 查询最近24小时内高威胁等级的事件 ====")
        
    #     # 构建查询
    #     question = "查询最近24小时内威胁等级大于等于3的安全事件，按威胁等级降序排序"
    #     print(f"\n问题: {question}")
        
    #     # 生成SQL查询
    #     raw_sql_query = self.sql_chain.generate_sql(question, ['ids_ai'])
        
    #     # 提取实际的SQL语句
    #     clean_sql = self.sql_chain._extract_sql(raw_sql_query)
    #     self.current_sql = clean_sql  # 保存当前SQL以便格式化结果
        
    #     # 打印SQL查询
    #     print("\n生成的原始SQL查询:")
    #     print("=" * 80)
    #     print(raw_sql_query)
    #     print("=" * 80)
        
    #     print("\n提取后的SQL查询:")
    #     print("=" * 80)
    #     print(clean_sql)
    #     print("=" * 80)
        
    #     # 验证SQL查询包含关键元素
    #     self.assertIn("ids_ai", raw_sql_query)
    #     self.assertIn("threat_level", raw_sql_query)
    #     self.assertIn("event_time", raw_sql_query)
        
    #     # 执行SQL查询
    #     try:
    #         result = self.sql_chain.execute_sql(raw_sql_query)
            
    #         # 格式化并显示结果
    #         formatted_result = self.format_result(result)
    #         print("\n查询结果:")
    #         print("=" * 80)
    #         print(formatted_result)
    #         print("=" * 80)
            
    #     except Exception as e:
    #         logger.error(f"执行SQL查询失败: {e}")
    #         self.fail(f"执行SQL查询失败: {e}")
        
    #     # 查询并回答
    #     try:
    #         answer = self.sql_chain.query_and_answer(question, ['ids_ai'])
    #         print("\n生成的回答:")
    #         print("=" * 80)
    #         print(answer)
    #         print("=" * 80)
    #         self.assertIsNotNone(answer)
    #     except Exception as e:
    #         logger.error(f"查询并回答失败: {e}")
    #         self.fail(f"查询并回答失败: {e}")
    
    # def test_specific_attack_category(self):
    #     """测试用例2: 查询特定攻击类别的事件"""
    #     logger.info("\n\n==== 测试用例2: 查询特定攻击类别的事件 ====")
        
    #     # 构建查询
    #     question = "查询过去一周内类别为'恶意软件'或'网络钓鱼'的攻击事件，显示事件时间、源IP、目标IP和威胁等级"
    #     print(f"\n问题: {question}")
        
    #     # 生成SQL查询
    #     raw_sql_query = self.sql_chain.generate_sql(question, ['ids_ai'])
        
    #     # 提取实际的SQL语句
    #     clean_sql = self.sql_chain._extract_sql(raw_sql_query)
    #     self.current_sql = clean_sql  # 保存当前SQL以便格式化结果
        
    #     # 打印SQL查询
    #     print("\n生成的原始SQL查询:")
    #     print("=" * 80)
    #     print(raw_sql_query)
    #     print("=" * 80)
        
    #     print("\n提取后的SQL查询:")
    #     print("=" * 80)
    #     print(clean_sql)
    #     print("=" * 80)
        
    #     # 验证SQL查询包含关键元素
    #     self.assertIn("ids_ai", raw_sql_query)
    #     self.assertIn("category", raw_sql_query)
    #     self.assertIn("event_time", raw_sql_query)
    #     self.assertIn("src_ip", raw_sql_query)
    #     self.assertIn("dst_ip", raw_sql_query)
        
    #     # 执行SQL查询
    #     try:
    #         result = self.sql_chain.execute_sql(raw_sql_query)
            
    #         # 格式化并显示结果
    #         formatted_result = self.format_result(result)
    #         print("\n查询结果:")
    #         print("=" * 80)
    #         print(formatted_result)
    #         print("=" * 80)
            
    #     except Exception as e:
    #         logger.error(f"执行SQL查询失败: {e}")
    #         self.fail(f"执行SQL查询失败: {e}")
        
    #     # 查询并回答
    #     try:
    #         answer = self.sql_chain.query_and_answer(question, ['ids_ai'])
    #         print("\n生成的回答:")
    #         print("=" * 80)
    #         print(answer)
    #         print("=" * 80)
    #         self.assertIsNotNone(answer)
    #     except Exception as e:
    #         logger.error(f"查询并回答失败: {e}")
    #         self.fail(f"查询并回答失败: {e}")
    
    # def test_traffic_analysis(self):
    #     """测试用例3: 流量分析"""
    #     logger.info("\n\n==== 测试用例3: 流量分析 ====")
        
    #     # 构建查询
    #     question = "分析昨天的网络流量，计算每个源IP发送的总字节数，只显示发送超过1MB(1048576字节)的IP，按发送量降序排序"
    #     print(f"\n问题: {question}")
        
    #     # 生成SQL查询
    #     raw_sql_query = self.sql_chain.generate_sql(question, ['ids_ai'])
        
    #     # 提取实际的SQL语句
    #     clean_sql = self.sql_chain._extract_sql(raw_sql_query)
    #     self.current_sql = clean_sql  # 保存当前SQL以便格式化结果
        
    #     # 打印SQL查询
    #     print("\n生成的原始SQL查询:")
    #     print("=" * 80)
    #     print(raw_sql_query)
    #     print("=" * 80)
        
    #     print("\n提取后的SQL查询:")
    #     print("=" * 80)
    #     print(clean_sql)
    #     print("=" * 80)
        
    #     # 验证SQL查询包含关键元素
    #     self.assertIn("ids_ai", raw_sql_query)
    #     self.assertIn("src_ip", raw_sql_query)
    #     self.assertIn("bytes_to_server", raw_sql_query)
    #     self.assertIn("SUM", raw_sql_query.upper())
    #     self.assertIn("GROUP BY", raw_sql_query.upper())
        
    #     # 执行SQL查询
    #     try:
    #         result = self.sql_chain.execute_sql(raw_sql_query)
            
    #         # 格式化并显示结果
    #         formatted_result = self.format_result(result)
    #         print("\n查询结果:")
    #         print("=" * 80)
    #         print(formatted_result)
    #         print("=" * 80)
            
    #     except Exception as e:
    #         logger.error(f"执行SQL查询失败: {e}")
    #         self.fail(f"执行SQL查询失败: {e}")
        
    #     # 查询并回答
    #     try:
    #         answer = self.sql_chain.query_and_answer(question, ['ids_ai'])
    #         print("\n生成的回答:")
    #         print("=" * 80)
    #         print(answer)
    #         print("=" * 80)
    #         self.assertIsNotNone(answer)
    #     except Exception as e:
    #         logger.error(f"查询并回答失败: {e}")
    #         self.fail(f"查询并回答失败: {e}")
    
    # def test_attack_pattern_analysis(self):
    #     """测试用例4: 攻击模式分析"""
    #     logger.info("\n\n==== 测试用例4: 攻击模式分析 ====")
        
    #     # 构建查询
    #     question = "分析本月初至今的攻击模式，统计不同攻击阶段的事件数量，按事件数量降序排序"
    #     print(f"\n问题: {question}")
        
    #     # 生成SQL查询
    #     raw_sql_query = self.sql_chain.generate_sql(question, ['ids_ai'])
        
    #     # 提取实际的SQL语句
    #     clean_sql = self.sql_chain._extract_sql(raw_sql_query)
    #     self.current_sql = clean_sql  # 保存当前SQL以便格式化结果
        
    #     # 打印SQL查询
    #     print("\n生成的原始SQL查询:")
    #     print("=" * 80)
    #     print(raw_sql_query)
    #     print("=" * 80)
        
    #     print("\n提取后的SQL查询:")
    #     print("=" * 80)
    #     print(clean_sql)
    #     print("=" * 80)
        
    #     # 验证SQL查询包含关键元素
    #     self.assertIn("ids_ai", raw_sql_query)
    #     self.assertIn("attack_step", raw_sql_query)
    #     self.assertIn("COUNT", raw_sql_query.upper())
    #     self.assertIn("GROUP BY", raw_sql_query.upper())
        
    #     # 执行SQL查询
    #     try:
    #         result = self.sql_chain.execute_sql(raw_sql_query)
            
    #         # 格式化并显示结果
    #         formatted_result = self.format_result(result)
    #         print("\n查询结果:")
    #         print("=" * 80)
    #         print(formatted_result)
    #         print("=" * 80)
            
    #     except Exception as e:
    #         logger.error(f"执行SQL查询失败: {e}")
    #         self.fail(f"执行SQL查询失败: {e}")
        
    #     # 查询并回答
    #     try:
    #         answer = self.sql_chain.query_and_answer(question, ['ids_ai'])
    #         print("\n生成的回答:")
    #         print("=" * 80)
    #         print(answer)
    #         print("=" * 80)
    #         self.assertIsNotNone(answer)
    #     except Exception as e:
    #         logger.error(f"查询并回答失败: {e}")
    #         self.fail(f"查询并回答失败: {e}")
    
    # def test_specific_time_range(self):
    #     """测试用例5: 特定时间范围查询"""
    #     logger.info("\n\n==== 测试用例5: 特定时间范围查询 ====")
        
    #     # 构建查询
    #     question = "前天下午3点到昨天晚上8点之间发生的所有威胁等级为4或5的安全事件，显示事件时间、设备名称、源IP、目标IP和攻击特征"
    #     print(f"\n问题: {question}")
        
    #     # 生成SQL查询
    #     raw_sql_query = self.sql_chain.generate_sql(question, ['ids_ai'])
        
    #     # 提取实际的SQL语句
    #     clean_sql = self.sql_chain._extract_sql(raw_sql_query)
    #     self.current_sql = clean_sql  # 保存当前SQL以便格式化结果
        
    #     # 打印SQL查询
    #     print("\n生成的原始SQL查询:")
    #     print("=" * 80)
    #     print(raw_sql_query)
    #     print("=" * 80)
        
    #     print("\n提取后的SQL查询:")
    #     print("=" * 80)
    #     print(clean_sql)
    #     print("=" * 80)
        
    #     # 验证SQL查询包含关键元素
    #     self.assertIn("ids_ai", raw_sql_query)
    #     self.assertIn("event_time", raw_sql_query)
    #     self.assertIn("threat_level", raw_sql_query)
    #     self.assertIn("device_name", raw_sql_query)
    #     self.assertIn("src_ip", raw_sql_query)
    #     self.assertIn("dst_ip", raw_sql_query)
    #     self.assertIn("signature", raw_sql_query)
        
    #     # 执行SQL查询
    #     try:
    #         result = self.sql_chain.execute_sql(raw_sql_query)
            
    #         # 格式化并显示结果
    #         formatted_result = self.format_result(result)
    #         print("\n查询结果:")
    #         print("=" * 80)
    #         print(formatted_result)
    #         print("=" * 80)
            
    #     except Exception as e:
    #         logger.error(f"执行SQL查询失败: {e}")
    #         self.fail(f"执行SQL查询失败: {e}")
        
    #     # 查询并回答
    #     try:
    #         answer = self.sql_chain.query_and_answer(question, ['ids_ai'])
    #         print("\n生成的回答:")
    #         print("=" * 80)
    #         print(answer)
    #         print("=" * 80)
    #         self.assertIsNotNone(answer)
    #     except Exception as e:
    #         logger.error(f"查询并回答失败: {e}")
    #         self.fail(f"查询并回答失败: {e}")
    
    def test_vague_query(self):
        """测试用例6: 模糊查询 - 处理不精确的自然语言问题"""
        logger.info("\n\n==== 测试用例6: 模糊查询 - 前24小时有无网络攻击风险 ====")
        
        # 构建模糊查询
        question = "前24小时有无网络攻击风险"
        print(f"\n问题: {question}")
        
        # 生成SQL查询
        raw_sql_query = self.sql_chain.generate_sql(question, ['ids_ai'])
        
        # 提取实际的SQL语句
        clean_sql = self.sql_chain._extract_sql(raw_sql_query)
        self.current_sql = clean_sql  # 保存当前SQL以便格式化结果
        
        # 打印SQL查询
        print("\n生成的原始SQL查询:")
        print("=" * 80)
        print(raw_sql_query)
        print("=" * 80)
        
        print("\n提取后的SQL查询:")
        print("=" * 80)
        print(clean_sql)
        print("=" * 80)
        
        # 验证SQL查询包含关键元素 - 对于模糊查询，我们期望至少包含时间和风险相关字段
        self.assertIn("ids_ai", raw_sql_query)
        self.assertIn("event_time", raw_sql_query)
        
        # 执行SQL查询
        try:
            result = self.sql_chain.execute_sql(raw_sql_query)
            
            # 格式化并显示结果
            formatted_result = self.format_result(result)
            print("\n查询结果:")
            print("=" * 80)
            print(formatted_result)
            print("=" * 80)
            
        except Exception as e:
            logger.error(f"执行SQL查询失败: {e}")
            self.fail(f"执行SQL查询失败: {e}")
        
        # 查询并回答
        try:
            answer = self.sql_chain.query_and_answer(question, ['ids_ai'])
            print("\n生成的回答:")
            print("=" * 80)
            print(answer)
            print("=" * 80)
            self.assertIsNotNone(answer)
            
            # 验证回答中包含风险评估相关内容
            risk_terms = ["风险", "攻击", "威胁", "安全", "事件"]
            has_risk_term = any(term in answer for term in risk_terms)
            self.assertTrue(has_risk_term, "回答中应包含风险评估相关内容")
            
        except Exception as e:
            logger.error(f"查询并回答失败: {e}")
            self.fail(f"查询并回答失败: {e}")
        
        # # 额外测试：尝试更模糊的后续问题
        # follow_up_question = "这些攻击有多严重？"
        # print(f"\n后续问题: {follow_up_question}")
        
        # try:
        #     # 构建上下文增强的问题
        #     enhanced_question = f"基于前面的查询结果，{follow_up_question}。原始问题是：{question}"
            
        #     # 查询并回答
        #     follow_up_answer = self.sql_chain.query_and_answer(enhanced_question, ['ids_ai'])
        #     print("\n后续问题的回答:")
        #     print("=" * 80)
        #     print(follow_up_answer)
        #     print("=" * 80)
        #     self.assertIsNotNone(follow_up_answer)
            
        # except Exception as e:
        #     logger.error(f"后续问题回答失败: {e}")
        #     # 这里我们不让测试失败，因为这是额外测试
        #     print(f"后续问题回答失败: {e}")

if __name__ == '__main__':
    unittest.main()