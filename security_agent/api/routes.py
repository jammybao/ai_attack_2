'''
Description: 
version: 
Author: Bao Jiaming
Date: 2025-03-04 12:43:49
LastEditTime: 2025-03-04 12:44:35
FilePath: \security_agent\api\routes.py
'''
"""
API路由定义
"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import datetime

from security_agent.chains.security_agent_chain import SecurityAgentChain
from security_agent.chains.sql_generator_chain import SQLGeneratorChain
from security_agent.config import settings

router = APIRouter()

class SecurityQuery(BaseModel):
    """安全查询请求模型"""
    query: str  # 用户自然语言查询，如"前8小时是否有网络安全攻击风险"

class TimeRange(BaseModel):
    """时间范围模型"""
    start_time: str
    end_time: str
    description: Optional[str] = None

class SecurityReportRequest(BaseModel):
    """安全报告请求模型"""
    report_type: str = "general"  # general, high_risk, login_failure, attack
    hours: int = 8  # 报告时间范围，默认为8小时
    custom_time_range: Optional[TimeRange] = None  # 自定义时间范围

class RiskAnalysisResult(BaseModel):
    """风险分析结果模型"""
    timestamp: datetime.datetime
    time_range: str
    has_risk: bool
    risk_level: str
    risk_type: Optional[str] = None
    analysis: str
    recommendations: List[str]

class SecurityReport(BaseModel):
    """安全报告模型"""
    timestamp: datetime.datetime
    report_type: str
    time_range: str
    report_content: str
    summary: str

class SQLQueryRequest(BaseModel):
    """SQL查询请求模型"""
    question: str  # 自然语言问题
    time_range: Optional[TimeRange] = None  # 可选的时间范围

class SQLQueryResult(BaseModel):
    """SQL查询结果模型"""
    question: str
    sql_query: str
    result: Any
    answer: str

def get_security_chain():
    """获取安全代理链的依赖注入函数"""
    config = {
        "tongyi_api_key": settings.TONGYI_API_KEY,
        "tongyi_model_name": settings.TONGYI_MODEL_NAME,
        "tongyi_base_url": settings.TONGYI_BASE_URL,
        "db_connection_string": settings.DB_CONNECTION_STRING,
        "security_logs_table": settings.SECURITY_LOGS_TABLE
    }
    return SecurityAgentChain(config)

def get_sql_chain():
    """获取SQL生成链的依赖注入函数"""
    sql_chain = SQLGeneratorChain(
        api_key=settings.TONGYI_API_KEY,
        table_name=settings.SECURITY_LOGS_TABLE,
        model_name=settings.TONGYI_MODEL_NAME,
        base_url=settings.TONGYI_BASE_URL
    )
    # 连接到数据库
    sql_chain.connect_to_database(settings.DB_CONNECTION_STRING)
    return sql_chain

@router.post("/security/analyze", response_model=RiskAnalysisResult)
async def analyze_security_logs(query: SecurityQuery, security_chain: SecurityAgentChain = Depends(get_security_chain)):
    """分析网络安全日志"""
    try:
        result = await security_chain.run(query.query)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/security/report", response_model=SecurityReport)
async def generate_security_report(
    request: SecurityReportRequest, 
    sql_chain: SQLGeneratorChain = Depends(get_sql_chain)
):
    """生成安全报告
    
    可用的报告类型:
    - general: 一般安全概况报告
    - high_risk: 高风险安全事件报告
    - login_failure: 登录失败记录报告
    - attack: 网络攻击事件报告
    """
    try:
        # 如果提供了自定义时间范围，使用自定义时间范围
        if request.custom_time_range:
            time_range = {
                "start_time": request.custom_time_range.start_time,
                "end_time": request.custom_time_range.end_time,
                "description": request.custom_time_range.description or f"自定义时间范围的{request.report_type}安全报告",
                "formatted_range": f"从 {request.custom_time_range.start_time} 到 {request.custom_time_range.end_time}"
            }
            report_content = await sql_chain.analyze_security_logs(
                time_range["description"], 
                time_range
            )
        else:
            # 否则使用小时数生成报告
            report_content = await sql_chain.scheduled_security_report(
                report_type=request.report_type,
                hours=request.hours
            )
        
        # 提取报告摘要（取前200个字符）
        summary = report_content[:200] + "..." if len(report_content) > 200 else report_content
        
        # 构建时间范围字符串
        if request.custom_time_range:
            time_range_str = f"从 {request.custom_time_range.start_time} 到 {request.custom_time_range.end_time}"
        else:
            now = datetime.datetime.now()
            past_time = now - datetime.timedelta(hours=request.hours)
            time_range_str = f"从 {past_time.strftime('%Y-%m-%d %H:%M:%S')} 到 {now.strftime('%Y-%m-%d %H:%M:%S')}"
        
        return SecurityReport(
            timestamp=datetime.datetime.now(),
            report_type=request.report_type,
            time_range=time_range_str,
            report_content=report_content,
            summary=summary
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/security/query", response_model=SQLQueryResult)
async def query_security_database(
    request: SQLQueryRequest, 
    sql_chain: SQLGeneratorChain = Depends(get_sql_chain)
):
    """查询安全数据库并返回结果"""
    try:
        # 如果提供了时间范围，将其添加到问题中
        if request.time_range:
            question = f"{request.question}，时间范围从{request.time_range.start_time}到{request.time_range.end_time}"
        else:
            question = request.question
        
        # 生成SQL查询
        sql_query = sql_chain.query_chain.invoke({"question": question})
        
        # 执行查询
        result = sql_chain.execute_tool.invoke({"query": sql_query})
        
        # 生成回答
        answer = await sql_chain.query_and_answer(question)
        
        return SQLQueryResult(
            question=question,
            sql_query=sql_query,
            result=result,
            answer=answer
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/security/scheduled_report/{report_type}")
async def scheduled_report(
    report_type: str = "general", 
    hours: int = 8,
    sql_chain: SQLGeneratorChain = Depends(get_sql_chain)
):
    """定时安全报告接口，可通过定时任务调用
    
    可用的报告类型:
    - general: 一般安全概况报告
    - high_risk: 高风险安全事件报告
    - login_failure: 登录失败记录报告
    - attack: 网络攻击事件报告
    """
    try:
        report_content = await sql_chain.scheduled_security_report(
            report_type=report_type,
            hours=hours
        )
        
        # 提取报告摘要
        summary = report_content[:200] + "..." if len(report_content) > 200 else report_content
        
        # 构建时间范围字符串
        now = datetime.datetime.now()
        past_time = now - datetime.timedelta(hours=hours)
        time_range_str = f"从 {past_time.strftime('%Y-%m-%d %H:%M:%S')} 到 {now.strftime('%Y-%m-%d %H:%M:%S')}"
        
        return SecurityReport(
            timestamp=datetime.datetime.now(),
            report_type=report_type,
            time_range=time_range_str,
            report_content=report_content,
            summary=summary
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) 