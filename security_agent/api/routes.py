'''
Description: 
version: 
Author: Bao Jiaming
Date: 2025-03-08 12:11:05
LastEditTime: 2025-03-24 03:09:23
FilePath: \security_agent\api\routes.py
'''
'''
Description: API路由定义
version: 2.0
Date: 2025-03-23
'''
"""
API路由定义 - 简化版，专用于调用OfficialSQLChain
"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import List, Optional, Dict, Any

from security_agent.chains.official_sql_chain import OfficialSQLChain
from security_agent.config import settings

router = APIRouter()

class SQLQueryRequest(BaseModel):
    """SQL查询请求模型"""
    question: str  # 自然语言问题
    table_names: Optional[List[str]] = None  # 可选的表名列表

class SQLQueryResponse(BaseModel):
    """SQL查询响应模型"""
    question: str
    answer: str

def get_official_sql_chain():
    """获取官方SQL查询链的依赖注入函数"""
    return OfficialSQLChain(
        api_key=settings.TONGYI_API_KEY,
        db_connection=settings.DB_CONNECTION_STRING,
        model_name=settings.TONGYI_MODEL_NAME,
        base_url=settings.TONGYI_BASE_URL
    )

@router.post("/sql/query", response_model=SQLQueryResponse)
async def query_database(
    request: SQLQueryRequest, 
    sql_chain: OfficialSQLChain = Depends(get_official_sql_chain)
):
    """查询数据库并返回结果
    
    Args:
        request: 包含问题和可选表名的请求对象
        sql_chain: 官方SQL查询链实例
        
    Returns:
        包含问题和回答的响应对象
    """
    try:
        # 调用官方SQL链的query_and_answer方法
        answer = sql_chain.query_and_answer(
            question=request.question,
            table_names=request.table_names
        )
        
        return SQLQueryResponse(
            question=request.question,
            answer=answer
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) 