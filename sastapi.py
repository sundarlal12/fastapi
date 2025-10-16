import os
from dotenv import load_dotenv
import mysql.connector
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, validator
from typing import Optional, List
from fastapi.middleware.cors import CORSMiddleware 
import subprocess
import uuid
import re
from enum import Enum

# Load .env values
load_dotenv()

# Get DB config from .env
DB_CONFIG = {
    "user": os.getenv("DB_USERNAME"),
    "password": os.getenv("DB_PASSWORD"),
    "host": os.getenv("DB_HOST"),
    "database": os.getenv("DB_NAME"),
    "port": int(os.getenv("DB_PORT","5432"))
}

app = FastAPI()
scan_status_store = {}



app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Or replace with ['https://your-frontend.com']
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


ALLOWED_PLATFORMS = {"github", "gitlab", "bitbucket", "web", "other"}
SCRIPT_MAP = {
    "github": "scr3_threads2.py",
    "gitlab": "scr3_threads_gitlab.py",
    "bitbucket": "scr3_threads_bitbucket.py",
    "other": "scr.py",
    "web": "scr.py"
}

def validate_filename_pattern(file: str) -> bool:
    return re.match(r'^[\w.\-*/]+$', file) is not None



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
    branch: str

# class ScanRequest(BaseModel):
#     username: str
#     reponame: str
#     branch: str
#     platform: str  # New field added

# class ScanRequest(BaseModel):
#     username: str
#     reponame: str
#     branch: str
#     platform: str

#     @validator('username', 'reponame', 'branch')
#     def validate_input(cls, v):
#         if not re.match(r'^[a-zA-Z0-9._\-]+$', v):
#             raise ValueError("Invalid characters in input.")
#         return v

#     @validator('platform')
#     def validate_platform(cls, v):
#         if v.lower() not in ALLOWED_PLATFORMS:
#             raise ValueError(f"Unsupported platform: {v}")
#         return v.lower()

# class ScanRequest(BaseModel):
#     username: str
#     reponame: str
#     branch: str
#     platform: str
#     include_files: Optional[List[str]] = []
#     exclude_files: Optional[List[str]] = []

#     @validator('username', 'reponame', 'branch')
#     def validate_identifier(cls, v):
#         if not re.match(r'^[a-zA-Z0-9._\-]+$', v):
#             raise ValueError("Invalid characters in username, repo or branch.")
#         return v

#     @validator('platform')
#     def validate_platform(cls, v):
#         if v.lower() not in ALLOWED_PLATFORMS:
#             raise ValueError(f"Unsupported platform: {v}")
#         return v.lower()

#     @validator('include_files', 'exclude_files', each_item=True)
#     def validate_file_patterns(cls, v):
#         if not validate_filename_pattern(v):
#             raise ValueError(f"Invalid file pattern: {v}")
#         return v

class ScanRequest(BaseModel):
    username: str
    repo_name: str
    branch: str
    platform: str
    include_files: Optional[List[str]] = []
    exclude_files: Optional[List[str]] = []

    @validator('username', 'repo_name', 'branch')
    def validate_identifier(cls, v):
        if not re.match(r'^[a-zA-Z0-9._\-]+$', v):
            raise ValueError("Invalid characters in username, repo_name or branch.")
        return v

    @validator('platform')
    def validate_platform(cls, v):
        if v.lower() not in SCRIPT_MAP:
            raise ValueError(f"Unsupported platform: {v}")
        return v.lower()

    @validator('include_files', 'exclude_files', each_item=True)
    def validate_file_patterns(cls, v):
        if not validate_filename_pattern(v):
            raise ValueError(f"Invalid file pattern: {v}")
        return v




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


"""
@app.post("/doscan")
async def do_scan(request: ScanRequest):
    try:
        # Build the command with the new platform argument
        cmd = ["python3", "scr3.py", request.username, request.reponame, request.branch, request.platform]

        # Run the script
        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode != 0:
            raise HTTPException(status_code=500, detail=f"Scan failed: {result.stderr}")

        return {"message": "Scan completed successfully", "output": result.stdout}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
"""
"""
@app.post("/doscan")
async def do_scan(request: ScanRequest):
    try:
        cmd = [
            "python3",
            "scr3.py",
            request.username,
            request.reponame,
            request.branch,
            request.platform
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

        if result.returncode != 0:
            raise HTTPException(status_code=500, detail=f"Scan failed: {result.stderr}")

        return {
            "message": "Scan completed successfully",
            "output": result.stdout
        }

    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=500, detail="Scan timed out.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
"""
"""
@app.post("/doscan")
async def do_scan(request: ScanRequest):
    try:
        script_name = SCRIPT_MAP[request.platform.lower()]
        cmd = [
            "python3",
            script_name,
            request.username,
            request.reponame,
            request.branch,
            request.platform
        ]

        if request.include_files:
            cmd.append("--include")
            cmd.append(','.join(request.include_files))

        if request.exclude_files:
            cmd.append("--exclude")
            cmd.append(','.join(request.exclude_files))
            
        
        scan_id = str(uuid.uuid4())
        scan_status_store[scan_id] = {"status": "in progress"}


        try:
            subprocess.Popen(cmd)
            return {"status": "Scan started", "scan_id": scan_id}
            
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Error launching scan: {str(e)}")


        # result = subprocess.Popen(cmd)

        # if result.returncode != 0:
        #     raise HTTPException(status_code=500, detail=f"Scan failed: {result.stderr.strip()}")

        # return {
        #     "message": "Scan completed successfully"
           
        # }

    # except subprocess.TimeoutExpired:
    #     raise HTTPException(status_code=500, detail="Scan timed out.")
    # except Exception as e:
    #     raise HTTPException(status_code=500, detail=f"Unexpected error: {str(e)}")

"""
@app.post("/doscan")
async def do_scan(request: ScanRequest):
    try:
        script_name = SCRIPT_MAP[request.platform.lower()]
        cmd = [
            "python3",
            script_name,
            request.username,
            request.repo_name,
            request.branch,
            request.platform
        ]

        if request.include_files:
            cmd.append("--include")
            cmd.append(','.join(request.include_files))

        if request.exclude_files:
            cmd.append("--exclude")
            cmd.append(','.join(request.exclude_files))
        
        scan_id = str(uuid.uuid4())
        scan_status_store[scan_id] = {"status": "in progress"}

        try:
            subprocess.Popen(cmd)
            return {"status": "Scan started", "scan_id": scan_id}
        
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Error launching scan: {str(e)}")
    
    except Exception as outer_e:
        raise HTTPException(status_code=500, detail=f"Unexpected error: {str(outer_e)}")



@app.post("/get/{table_name}")
def get_data(table_name: str, request: GetDataRequest):
    allowed_tables = [
        "dead_code_info",
        "docstring_info",
        "malicious_code_info",
        "owasp_security_info",
        "secrets_info",
        "smelly_code_info",
        "sca_info",
        "infra_security_info"
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
