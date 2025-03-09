"""
时间解析链单元测试
"""
import unittest
from unittest.mock import patch, MagicMock
import json
from datetime import datetime, timedelta

from security_agent.chains.time_parser_chain import TimeRangeParserChain

class TestTimeRangeParserChain(unittest.TestCase):
    """时间解析链单元测试"""
    
    def setUp(self):
        """测试前准备"""
        self.api_key = "fake_api_key"
        
        # 模拟LLM和链
        self.patcher = patch('security_agent.chains.time_parser_chain.ChatOpenAI')
        self.mock_llm = self.patcher.start()
        
        # 创建解析链实例
        self.time_parser = TimeRangeParserChain(self.api_key)
        
        # 模拟链的调用结果
        self.mock_chain = MagicMock()
        self.time_parser.chain = self.mock_chain
    
    def tearDown(self):
        """测试后清理"""
        self.patcher.stop()
    
    async def test_parse_time_range_success(self):
        """测试成功解析时间范围"""
        # 模拟当前时间
        current_time = datetime(2025, 3, 1, 12, 0, 0)
        
        # 模拟解析结果
        expected_result = {
            "start_time": "2025-03-01 04:00:00",
            "end_time": "2025-03-01 12:00:00",
            "description": "前8小时",
            "formatted_range": "2025-03-01 04:00:00 至 2025-03-01 12:00:00"
        }
        
        # 设置模拟链的返回值
        self.mock_chain.ainvoke.return_value = expected_result
        
        # 调用解析函数
        with patch('security_agent.chains.time_parser_chain.datetime') as mock_datetime:
            mock_datetime.now.return_value = current_time
            result = await self.time_parser.parse_time_range("前8小时是否有网络安全攻击风险")
        
        # 验证结果
        self.assertEqual(result, expected_result)
        self.mock_chain.ainvoke.assert_called_once()
    
    async def test_parse_time_range_failure(self):
        """测试解析失败时的默认行为"""
        # 模拟当前时间
        current_time = datetime(2025, 3, 1, 12, 0, 0)
        
        # 设置模拟链抛出异常
        self.mock_chain.ainvoke.side_effect = Exception("解析失败")
        
        # 调用解析函数
        with patch('security_agent.chains.time_parser_chain.datetime') as mock_datetime:
            mock_datetime.now.return_value = current_time
            result = await self.time_parser.parse_time_range("无效的时间描述")
        
        # 验证结果
        self.assertEqual(result["start_time"], (current_time - timedelta(hours=24)).strftime("%Y-%m-%d %H:%M:%S"))
        self.assertEqual(result["end_time"], current_time.strftime("%Y-%m-%d %H:%M:%S"))
        self.assertEqual(result["description"], "默认时间范围（最近24小时）")
        self.assertIn("error", result)

if __name__ == "__main__":
    unittest.main() 