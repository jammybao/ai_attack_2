"""
API端点集成测试
"""
import unittest
from fastapi.testclient import TestClient
import os
import json
from unittest.mock import patch, MagicMock

from security_agent.main import app
from security_agent.chains.security_agent_chain import SecurityAgentChain

class TestAPIEndpoints(unittest.TestCase):
    """API端点集成测试"""
    
    def setUp(self):
        """测试前准备"""
        self.client = TestClient(app)
        
        # 模拟安全代理链
        self.patcher = patch('security_agent.api.routes.SecurityAgentChain')
        self.mock_chain_class = self.patcher.start()
        
        # 创建模拟链实例
        self.mock_chain = MagicMock()
        self.mock_chain_class.return_value = self.mock_chain
    
    def tearDown(self):
        """测试后清理"""
        self.patcher.stop()
    
    def test_health_check(self):
        """测试健康检查端点"""
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "healthy"})
    
    def test_analyze_security_logs_success(self):
        """测试安全日志分析端点成功情况"""
        # 模拟分析结果
        mock_result = {
            "timestamp": "2025-03-01T12:00:00",
            "time_range": "2025-03-01 04:00:00 至 2025-03-01 12:00:00",
            "has_risk": True,
            "risk_level": "中",
            "risk_type": "端口扫描",
            "analysis": "检测到来自IP 203.0.113.42的系统性端口扫描活动",
            "recommendations": ["临时阻止来源IP", "检查目标服务器"]
        }
        
        # 设置模拟链的返回值
        self.mock_chain.run.return_value = mock_result
        
        # 发送请求
        response = self.client.post(
            "/api/security/analyze",
            json={"query": "前8小时是否有网络安全攻击风险"}
        )
        
        # 验证结果
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["has_risk"], True)
        self.assertEqual(response.json()["risk_level"], "中")
        self.assertEqual(response.json()["risk_type"], "端口扫描")
        
        # 验证链被正确调用
        self.mock_chain.run.assert_called_once_with("前8小时是否有网络安全攻击风险")
    
    def test_analyze_security_logs_failure(self):
        """测试安全日志分析端点失败情况"""
        # 设置模拟链抛出异常
        self.mock_chain.run.side_effect = Exception("分析失败")
        
        # 发送请求
        response = self.client.post(
            "/api/security/analyze",
            json={"query": "前8小时是否有网络安全攻击风险"}
        )
        
        # 验证结果
        self.assertEqual(response.status_code, 500)
        self.assertIn("detail", response.json())

if __name__ == "__main__":
    unittest.main() 