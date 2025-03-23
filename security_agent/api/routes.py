'''
Description: 
version: 
Author: Bao Jiaming
Date: 2025-03-08 12:11:05
LastEditTime: 2025-03-24 06:05:10
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
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
import pandas as pd
import io
import os
import logging
from pathlib import Path
from sqlalchemy import create_engine, text

from security_agent.chains.official_sql_chain import OfficialSQLChain
from security_agent.chains.ml_security_chain import MLSecurityChain
from security_agent.config import settings

# 设置日志
logger = logging.getLogger(__name__)

router = APIRouter()

# 创建模型目录
MODEL_DIR = Path("./models")
MODEL_DIR.mkdir(exist_ok=True)

# 创建数据库引擎
db_engine = create_engine(settings.DB_CONNECTION_STRING)

class SQLQueryRequest(BaseModel):
    """SQL查询请求"""
    question: str = Field(..., description="用户问题")
    use_ml: bool = Field(True, description="是否使用机器学习增强分析")
    database_name: Optional[str] = Field(None, description="数据库名称")

class SQLQueryResponse(BaseModel):
    """SQL查询响应"""
    question: str = Field(..., description="原始问题")
    sql_query: str = Field(..., description="生成的SQL查询")
    sql_result: str = Field(..., description="SQL查询结果")
    security_analysis: Dict[str, Any] = Field(..., description="安全分析结果")
    formatted_answer: str = Field(..., description="格式化的回答")

class ModelTrainRequest(BaseModel):
    """模型训练请求"""
    anomaly_features: Optional[List[str]] = None  # 用于异常检测的特征
    attack_features: Optional[List[str]] = None  # 用于攻击链预测的特征
    attack_target: Optional[str] = None  # 攻击链预测的目标变量

class ModelTrainResponse(BaseModel):
    """模型训练响应"""
    success: bool
    message: str
    details: Dict[str, Any] = {}

def get_ml_chain():
    """获取机器学习安全链的依赖注入函数"""
    return MLSecurityChain(
        anomaly_model_path=os.path.join(MODEL_DIR, "anomaly_model.pkl") if os.path.exists(os.path.join(MODEL_DIR, "anomaly_model.pkl")) else None,
        ip_reputation_model_path=os.path.join(MODEL_DIR, "ip_reputation_model.pkl") if os.path.exists(os.path.join(MODEL_DIR, "ip_reputation_model.pkl")) else None,
        attack_chain_model_path=os.path.join(MODEL_DIR, "attack_chain_model.pkl") if os.path.exists(os.path.join(MODEL_DIR, "attack_chain_model.pkl")) else None
    )

def get_official_sql_chain():
    """获取官方SQL查询链的依赖注入函数"""
    # 获取机器学习安全链
    ml_chain = get_ml_chain()
    
    return OfficialSQLChain(
        api_key=settings.TONGYI_API_KEY,
        db_connection=settings.DB_CONNECTION_STRING,
        model_name=settings.TONGYI_MODEL_NAME,
        base_url=settings.TONGYI_BASE_URL,
        ml_chain=ml_chain
    )

@router.post("/query", response_model=SQLQueryResponse, tags=["SQL"])
async def query_database(request: SQLQueryRequest):
    """
    查询数据库并进行安全分析
    """
    try:
        # 获取SQL链
        sql_chain = get_official_sql_chain()
        if not sql_chain:
            error_message = "SQL链初始化失败"
            logger.error(error_message)
            raise HTTPException(
                status_code=500,
                detail=error_message
            )
        
        # 执行查询
        logger.info(f"执行查询: {request.question}")
        result = sql_chain.query_and_answer(request.question, use_ml=request.use_ml)
        
        # 格式化安全分析结果
        formatted_answer = format_security_analysis(result["security_analysis"])
        
        # 构建响应
        response = SQLQueryResponse(
            question=result["question"],
            sql_query=result["sql_query"],
            sql_result=result["sql_result"],
            security_analysis=result["security_analysis"],
            formatted_answer=formatted_answer
        )
        
        return response
    except Exception as e:
        error_message = f"查询数据库失败: {str(e)}"
        logger.error(error_message)
        raise HTTPException(
            status_code=500, 
            detail=error_message
        )

def format_security_analysis(analysis: Dict[str, Any]) -> str:
    """
    格式化安全分析结果为可读文本
    """
    if not analysis:
        return "无安全分析结果"
    
    # 如果有错误，返回错误信息
    if "error" in analysis:
        return f"安全分析错误: {analysis['error']}"
    
    # 构建格式化文本
    formatted_text = f"## 安全风险评估\n\n**风险等级**: {analysis.get('risk_level', '未知')}\n\n"
    
    # 添加关键发现
    if "key_findings" in analysis and analysis["key_findings"]:
        formatted_text += "### 关键发现\n\n"
        for i, finding in enumerate(analysis["key_findings"]):
            formatted_text += f"{i+1}. {finding}\n"
        formatted_text += "\n"
    
    # 添加安全建议
    if "recommendations" in analysis and analysis["recommendations"]:
        formatted_text += "### 安全建议\n\n"
        for i, recommendation in enumerate(analysis["recommendations"]):
            formatted_text += f"{i+1}. {recommendation}\n"
        formatted_text += "\n"
    
    # 添加IP分析
    if "ip_analysis" in analysis and analysis["ip_analysis"]:
        formatted_text += "### IP地址分析\n\n"
        formatted_text += analysis["ip_analysis"].replace("\n", "\n\n")
        formatted_text += "\n\n"
    
    # 添加机器学习分析
    if "ml_analysis" in analysis and analysis["ml_analysis"]:
        formatted_text += "### 机器学习分析\n\n"
        formatted_text += analysis["ml_analysis"]
        formatted_text += "\n\n"
    
    # 添加详细分析（如果有）
    if "detailed_analysis" in analysis and analysis["detailed_analysis"]:
        formatted_text += "### 详细分析\n\n"
        formatted_text += analysis["detailed_analysis"]
    
    return formatted_text

@router.post("/ml/train", response_model=ModelTrainResponse)
async def train_models(
    file: UploadFile = File(...),
    request: ModelTrainRequest = None,
    ml_chain: MLSecurityChain = Depends(get_ml_chain)
):
    """通过上传的CSV文件训练机器学习模型
    
    Args:
        file: 上传的CSV训练数据文件
        request: 训练请求参数
        ml_chain: 机器学习安全链实例
        
    Returns:
        训练结果响应
    """
    try:
        # 读取上传的CSV文件
        content = await file.read()
        uploaded_data = pd.read_csv(io.BytesIO(content))
        
        # 查询最近30天的数据用于训练
        with db_engine.connect() as conn:
            query = """
            SELECT 
                event_time, event_type, device_name, src_ip, threat_level, 
                category, attack_function, attack_step, signature, dst_ip, protocol,
                src_port, dst_port, bytes_to_server as bytes_sent, bytes_to_client as bytes_received
            FROM ids_ai
            WHERE event_time >= CURDATE() - INTERVAL 30 DAY
            ORDER BY event_time
            """
            result = conn.execute(text(query))
            df = pd.DataFrame(result.fetchall(), columns=result.keys())
        
        print(f"获取到{len(df)}条训练数据，时间范围: {df['event_time'].min()} 至 {df['event_time'].max()}")

        # 时间序列划分(前80%作为训练集，后20%作为测试集)
        train_size = int(len(df) * 0.8)
        train_df = df.iloc[:train_size]
        test_df = df.iloc[train_size:]

        print(f"训练集: {len(train_df)} 记录，测试集: {len(test_df)} 记录")
        print(f"训练集时间范围: {train_df['event_time'].min()} 至 {train_df['event_time'].max()}")
        print(f"测试集时间范围: {test_df['event_time'].min()} 至 {test_df['event_time'].max()}")

        # 保存为CSV
        train_csv_path = 'training_data.csv'
        test_csv_path = 'testing_data.csv'
        train_df.to_csv(train_csv_path, index=False)
        test_df.to_csv(test_csv_path, index=False)
        
        # 处理特征和目标
        # 1. 预处理数据，确保分类特征可以被使用
        df_processed = df.copy()
        
        # 2. 对分类特征进行编码
        categorical_features = ['category', 'attack_function', 'signature']
        for feature in categorical_features:
            if feature in df_processed.columns:
                # 填充空值
                if df_processed[feature].isna().sum() > 0:
                    df_processed[feature] = df_processed[feature].fillna('未知')
                # 对分类特征进行整数编码
                df_processed[feature + '_encoded'] = pd.factorize(df_processed[feature])[0]
        
        # 3. 准备特征
        # 默认使用数值列作为异常检测特征
        numeric_columns = df_processed.select_dtypes(include=['number']).columns.tolist()
        if not request or not request.anomaly_features:
            anomaly_features = numeric_columns
        else:
            anomaly_features = request.anomaly_features
        
        # 攻击链特征 - 强调attack_function和signature
        if not request or not request.attack_features:
            # 默认使用数值特征以及编码后的分类特征，特别是attack_function和signature
            encoded_features = [f + '_encoded' for f in categorical_features if f + '_encoded' in df_processed.columns]
            attack_features = numeric_columns + encoded_features
        else:
            attack_features = request.attack_features
            
        # 攻击目标 - 不使用attack_step作为目标
        attack_target = "attack_function_encoded"  # 默认使用attack_function作为预测目标
        if request and request.attack_target:
            attack_target = request.attack_target
            
        print(f"训练使用的数据形状: {df_processed.shape}")
        print(f"异常检测特征: {anomaly_features}")
        print(f"攻击链预测特征: {attack_features}")
        print(f"攻击链预测目标: {attack_target}")
            
        # 训练模型 - 使用处理后的数据库数据
        results = ml_chain.train_models_from_data(
            data=df_processed,  # 修改为使用数据库数据
            anomaly_features=anomaly_features,
            attack_features=attack_features,
            attack_target=attack_target
        )
        
        # 保存模型
        if results.get("anomaly_model_trained", False):
            ml_chain.anomaly_model.save_model(os.path.join(MODEL_DIR, "anomaly_model.pkl"))
            
        if results.get("attack_model_trained", False):
            ml_chain.attack_chain_model.save_model(os.path.join(MODEL_DIR, "attack_chain_model.pkl"))
            
        if results.get("ip_reputation_updated", False):
            with open(os.path.join(MODEL_DIR, "ip_reputation_model.pkl"), 'wb') as f:
                pd.to_pickle(ml_chain.ip_reputation_model, f)
                
        # 返回结果
        success = any([
            results.get("anomaly_model_trained", False),
            results.get("attack_model_trained", False),
            results.get("ip_reputation_updated", False)
        ])
        
        return ModelTrainResponse(
            success=success,
            message="模型训练" + ("成功" if success else "失败"),
            details=results
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) 