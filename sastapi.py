import os
from dotenv import load_dotenv
import mysql.connector
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional, List
from fastapi.middleware.cors import CORSMiddleware 

# Load .env values
load_dotenv()

# Get DB config from .env
DB_CONFIG = {
    "user": os.getenv("DB_USERNAME"),
    "password": os.getenv("DB_PASSWORD"),
    "host": os.getenv("DB_HOST"),
    "database": os.getenv("DB_NAME")
}

app = FastAPI()


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Or replace with ['https://your-frontend.com']
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class Vulnerability(BaseModel):
    username: str
    email: str
    platform: str
    repo_name: str
    file_path: str
    line_number: int
    vulnerability_type: Optional[str]
    cwe: Optional[str]
    cve: Optional[str]
    severity: Optional[str]
    short_description: Optional[str]
    suggested_fix: Optional[str]
    bad_practice: Optional[str]
    good_practice: Optional[str]

class GetDataRequest(BaseModel):
    username: str
    platform: str
    repo_name: str

def get_db_connection():
    return mysql.connector.connect(**DB_CONFIG)

@app.post("/insert/{table_name}")
def insert_data(table_name: str, payload: List[Vulnerability]):
    allowed_tables = [
        "dead_code_info",
        "docstring_info",
        "malicious_code_info",
        "owasp_security_info",
        "secrets_info",
        "smelly_code_info"
    ]
    if table_name not in allowed_tables:
        raise HTTPException(status_code=400, detail="Invalid table name.")

    query = f"""
        INSERT INTO {table_name} (
            username, email, platform, repo_name, file_path, line_number, vulnerability_type,
            cwe, cve, severity, short_description, suggested_fix,
            bad_practice, good_practice
        ) VALUES (
            %(username)s, %(email)s, %(platform)s, %(repo_name)s, %(file_path)s, %(line_number)s,
            %(vulnerability_type)s, %(cwe)s, %(cve)s, %(severity)s, %(short_description)s,
            %(suggested_fix)s, %(bad_practice)s, %(good_practice)s
        )
    """

    db = get_db_connection()
    cursor = db.cursor()
    try:
        for item in payload:
            cursor.execute(query, item.dict())
        db.commit()
        return {"message": f"{len(payload)} records inserted","error":0}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cursor.close()
        db.close()

# @app.post("/get/{table_name}")
# def get_data(table_name: str, request: GetDataRequest):
#     allowed_tables = [
#         "dead_code_info",
#         "docstring_info",
#         "malicious_code_info",
#         "owasp_security_info",
#         "secrets_info",
#         "smelly_code_info"
#     ]
#     if table_name not in allowed_tables:
#         raise HTTPException(status_code=400, detail="Invalid table name.")

#     db = get_db_connection()
#     cursor = db.cursor(dictionary=True)
#     try:
#         cursor.execute(f"""
#             SELECT * FROM {table_name}
#             WHERE username = %s AND platform = %s AND repo_name = %s
#         """, (request.username, request.platform, request.repo_name))
#         result = cursor.fetchall()
#         return {"results": result}
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=str(e))
#     finally:
#         cursor.close()
#         db.close()

# @app.post("/get/{table_name}")
# def get_data(table_name: str, request: GetDataRequest):
#     allowed_tables = [
#         "dead_code_info",
#         "docstring_info",
#         "malicious_code_info",
#         "owasp_security_info",
#         "secrets_info",
#         "smelly_code_info"
#     ]
#     if table_name not in allowed_tables:
#         raise HTTPException(status_code=400, detail="Invalid table name.")

#     db = get_db_connection()
#     cursor = db.cursor(dictionary=True)
#     try:
#         cursor.execute(f"""
#             SELECT * FROM {table_name}
#             WHERE username = %s AND platform = %s AND repo_name = %s
#         """, (request.username, request.platform, request.repo_name))
        
#         result = cursor.fetchall()
#         count = len(result)

#         return {
#             "total": count,
#             "results": result
#         }
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=str(e))
#     finally:
#         cursor.close()
#         db.close()


# @app.post("/get/{table_name}")
# def get_data(table_name: str, request: GetDataRequest):
#     allowed_tables = [
#         "dead_code_info",
#         "docstring_info",
#         "malicious_code_info",
#         "owasp_security_info",
#         "secrets_info",
#         "smelly_code_info"
#     ]
#     if table_name not in allowed_tables:
#         raise HTTPException(status_code=400, detail="Invalid table name.")

#     db = get_db_connection()
#     cursor = db.cursor(dictionary=True)
#     try:
#         cursor.execute(f"""
#             SELECT * FROM {table_name}
#             WHERE username = %s AND platform = %s AND repo_name = %s
#         """, (request.username, request.platform, request.repo_name))

#         result = cursor.fetchall()

#         # Exclude 'email' from each row
#         filtered_result = [
#             {k: v for k, v in row.items() if k != "email"} for row in result
#         ]

#         return {
#             "count": len(filtered_result),
#             "results": filtered_result
#         }
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=str(e))
#     finally:
#         cursor.close()
#         db.close()

@app.post("/get/{table_name}")
def get_data(table_name: str, request: GetDataRequest):
    allowed_tables = [
        "dead_code_info",
        "docstring_info",
        "malicious_code_info",
        "owasp_security_info",
        "secrets_info",
        "smelly_code_info"
    ]
    if table_name not in allowed_tables:
        raise HTTPException(status_code=400, detail="Invalid API call.")

    db = get_db_connection()
    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute(f"""
            SELECT * FROM {table_name}
            WHERE username = %s AND platform = %s AND repo_name = %s AND branch = %s
        """, (request.username, request.platform, request.repo_name , request.branch))

        result = cursor.fetchall()

        # Exclude 'email' from each row
        filtered_result = [
            {k: v for k, v in row.items() if k != "email"} for row in result
        ]

        # Count severities
        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "informational": 0
        }

        for row in result:
            severity = (row.get("severity") or "").strip().lower()
            if severity in severity_counts:
                severity_counts[severity] += 1

        return {
            "count": len(filtered_result),
            "severity_counts": severity_counts,
            "results": filtered_result
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cursor.close()
        db.close()
