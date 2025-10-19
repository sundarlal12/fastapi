# scanner.py
#Author: Sundar Lal Baror

import tiktoken
import string
import secrets
import json
import psycopg2
from psycopg2.extras import RealDictCursor
from risk_analyzer import RiskAnalyzer
import sys
import os
import urllib.parse
import base64
import re
import urllib.parse
from json.decoder import JSONDecodeError
import fnmatch
import requests
import base64
import mysql.connector
from dotenv import load_dotenv
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import yaml
import regex as re
from pathlib import Path
import openai
import time
import random

# Load .env variables

MAX_RETRIES = 4
RETRY_DELAY = 3  # 

load_dotenv()
SITE_URL = os.getenv("SITE_URL")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OSV_API_URL = "https://api.osv.dev/v1/query"
MODEL = "gpt-4o"
client = openai.OpenAI(api_key=OPENAI_API_KEY)
EMAIL = ""
TOKEN = ""
DB_CONFIG = {
    "user": os.getenv("DB_USERNAME"),
    "password": os.getenv("DB_PASSWORD"),
    "host": os.getenv("DB_HOST"),
    "dbname": os.getenv("DB_NAME"),
    "port": int(os.getenv("DB_PORT", "5432")) 
}


DB_PORT = int(os.getenv("DB_PORT", "5432"))
DATABASE_URL = os.getenv("DATABASE_URL")
DB_SCHEMA = os.getenv("DB_SCHEMA", "sastcode_schema")


CATEGORIES = [
    "dead_code", "docstring", "malicious_code",
    "owasp_security", "secrets", "smelly_code"
]

CATEGORY_TABLE_MAP = {
    "dead_code": "dead_code_info",
    "docstring": "docstring_info",
    "malicious_code": "malicious_code_info",
    "owasp_security": "owasp_security_info",
    "secrets": "secrets_info",
    "smelly_code": "smelly_code_info"
}

ALLOWED_EXTENSIONS = {
    # Python
    '.py', '.pyw',
    
    # PHP & Frameworks
    '.php', '.phtml', '.php3', '.php4', '.php5', '.php7', '.phps',
    '.ctp',
    
    # ASP.NET
    '.asp', '.aspx', '.ashx', '.asmx', '.ascx',
    '.cs', '.vb',
    
    # JavaScript/TypeScript
    '.js', '.jsx', '.mjs', '.cjs',
    '.ts', '.tsx', '.mts', '.cts',
    
    # Java
    '.java', '.jsp', '.jspx',
    
    # C/C++
    '.c', '.cpp', '.cc', '.cxx', '.h', '.hpp',
    
    # Go
    '.go',
    
    # Rust
    '.rs',
    
    # Ruby
    '.rb', '.erb',
    
    # HTML/Templates
    # '.html', '.htm',
    '.ejs', '.j2', '.jinja', '.jinja2',
    
    # Shell Scripts
    '.sh', '.bash', '.ps1', '.bat', '.cmd',
    
    # WebAssembly
    '.wat', '.wasm',
    
    # DevOps/Infrastructure
    '.dockerfile', '.dockerignore',
    '.tf',
    '.pp',
    '.groovy',
    
    # Configuration
    '.yml', '.yaml',
    '.json', '.txt', '.xml'
}

EXCLUDED_PATTERNS = {
    "jquery*.js",    # jquery.js, jquery.min.js, jquery-3.6.0.js ...
    "*.min.js",      # any minified JS
    "*.bundle.js",   # bundles

    "vendor/*",      # anything in vendor folder
    "node_modules/*",# skip node_modules entirely if present
  



    "react*.js",
    "angular*.js",
    "vue*.js",
    "bootstrap*.js",
    "*.bootstrap*.js",
    "popper*.js",
    "*.popper*.js",

    # Common distribution/build/vendor directories (path-aware)
    "node_modules/*",
    "vendor/*",
    "dist/*",
    "build/*",
    "out/*",
    "__MACOSX/*"

}


SPECIAL_FILES = {"package.json", "requirements.txt", "pom.xml"}

# def get_db_connection():
#     return mysql.connector.connect(**DB_CONFIG)

def get_db_connection():
    """
    Create a connection to Supabase PostgreSQL using psycopg2.
    Sets the search_path to your schema automatically.
    """
    try:
        conn = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor, connect_timeout=5, sslmode="require")
        with conn.cursor() as cur:
            cur.execute(f"SET search_path TO {DB_SCHEMA};")
        return conn
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"DB unreachable: {e}")

def load_prompt_template(path="review_prompt.yml"):
    with open(path, "r") as file:
        yml = yaml.safe_load(file)
        return yml["review_template"]


def fix_hex_strings(s):
    # Fix invalid JSON escape sequences like \x47 to \\x47
    return re.sub(r'(?<!\\)(\\x[0-9a-fA-F]{2})', r'\\\1', s)


def escape_invalid_hex_sequences(json_str):

    return re.sub(r'(?<!\\)(\\x[0-9a-fA-F]{2})', r'\\\\x\1[2:]', json_str)



def extract_json_from_response(text):
    # print("---x----")
    # print(text[:1000])  # Print first 1000 chars to avoid huge outputs
    # print("---x----")

    # Phase 1: Ultra-resilient JSON extraction
    def extract_json_blocks(text):
        blocks = []
        stack = []
        start = -1
        in_string = False
        escape = False
        in_bad_practice = False
        
        for i, char in enumerate(text):
            # Track if we're entering bad_practice field
            if not in_string and text[i:i+13] == '"bad_practice"':
                in_bad_practice = True
            
            if not in_string:
                if char == '{':
                    if not stack:
                        start = i
                    stack.append(char)
                elif char == '}':
                    if stack:
                        stack.pop()
                        if not stack and start != -1:
                            blocks.append(text[start:i+1])
                            start = -1
                elif char == '"':
                    in_string = True
            else:
                if escape:
                    escape = False
                elif char == '\\':
                    escape = True
                elif char == '"':
                    in_string = False
                    in_bad_practice = False
                    
                # Special handling for bad_practice content
                if in_bad_practice and char == '"' and not escape:
                    # Find closing quote by looking ahead
                    end_quote = text.find('"', i+1)
                    if end_quote == -1:
                        # If no closing quote, terminate at next }
                        end_quote = text.find('}', i+1)
                        if end_quote == -1:
                            end_quote = len(text)-1
                    # Add artificial closing quote
                    text = text[:end_quote] + '"' + text[end_quote:]
                    in_string = False
                    in_bad_practice = False
        
        return blocks

    json_blocks = extract_json_blocks(text)
    
    if not json_blocks:
        print("❌ No valid JSON blocks found.")
        return None

    # Phase 2: Specialized sanitizer with multiple strategies
    def sanitize_and_parse(block):
        # Strategy 1: Direct parse attempt
        try:
            parsed = json.loads(block)
            # Ensure bad_practice is URL encoded
            if isinstance(parsed, dict):
                for key, value in parsed.items():
                    if key == 'malicious_code':
                        for path, findings in value.items():
                            for finding in findings:
                                if 'bad_practice' in finding:
                                    finding['bad_practice'] = urllib.parse.quote(finding['bad_practice'])
            return parsed
        except JSONDecodeError:
            pass

        # Strategy 2: Targeted field sanitization
        try:
            # Handle bad_practice field first
            def encode_bad_practice(match):
                content = match.group(1)
                try:
                    # Try to unescape hex codes first
                    unescaped = bytes(content, 'utf-8').decode('unicode-escape')
                    return f'"bad_practice": "{urllib.parse.quote(unescaped)}"'
                except:
                    return f'"bad_practice": "{urllib.parse.quote(content)}"'

            sanitized = re.sub(
                r'"bad_practice"\s*:\s*"((?:\\"|[^"])*?)"(?=\s*[,}])',
                encode_bad_practice,
                block,
                flags=re.DOTALL
            )

            # Fix other common JSON issues
            sanitized = re.sub(r',\s*([}\]])', r'\1', sanitized)  # Trailing commas
            sanitized = re.sub(r'([{,])\s*([^"\s]\S*?)\s*:', r'\1"\2":', sanitized)  # Unquoted keys
            
            return json.loads(sanitized)
        except JSONDecodeError as e:
            print(f"⚠️ JSON decode error after sanitization: {e}")
            print("Problematic portion:")
            print(block[max(0, e.pos-50):e.pos+50])
            return None

    # Phase 3: Process all found blocks
    for block in json_blocks:
        parsed = sanitize_and_parse(block)
        if parsed:
            return parsed

    print("❌ Failed to parse any JSON blocks")
    return None

def split_code_to_chunks_with_line_numbers(code_text, max_chunk_tokens=3000, model="gpt-4o"):
    encoder = tiktoken.encoding_for_model(model)
    lines = code_text.splitlines()
    
    chunks = []
    current_chunk_lines = []
    current_token_count = 0
    line_offset = 1  # Actual line number from original code

    for line in lines:
        encoded_line = encoder.encode(line + "\n")  # include newline
        line_token_len = len(encoded_line)

        if current_token_count + line_token_len > max_chunk_tokens:
            if current_chunk_lines:
                chunk_text = "\n".join(current_chunk_lines)
                chunks.append((line_offset - len(current_chunk_lines), chunk_text))
                current_chunk_lines = []
                current_token_count = 0

        current_chunk_lines.append(f"{line_offset}: {line}")
        current_token_count += line_token_len
        line_offset += 1

    if current_chunk_lines:
        chunk_text = "\n".join(current_chunk_lines)
        chunks.append((line_offset - len(current_chunk_lines), chunk_text))

    return chunks



def add_line_numbers(code):
    return "\n".join(f"{i+1}: {line}" for i, line in enumerate(code.splitlines()))


def split_code_to_chunks(code_text, max_chunk_tokens=3000, model="gpt-4o"):
    encoder = tiktoken.encoding_for_model(model)
    tokens = encoder.encode(code_text)

    chunks = []
    start = 0
    while start < len(tokens):
        end = min(start + max_chunk_tokens, len(tokens))
        chunk_tokens = tokens[start:end]
        chunk_text = encoder.decode(chunk_tokens)
        chunks.append(chunk_text)
        start = end
    return chunks



def merge_results(base, new):
    if not isinstance(base, dict):
        base = {}
    if not isinstance(new, dict):
        return base
    for key, val in new.items():
        if key not in base:
            base[key] = val
        elif isinstance(val, list) and isinstance(base.get(key), list):
            base[key].extend(val)
        elif isinstance(val, dict) and isinstance(base.get(key), dict):
            base[key] = merge_results(base[key], val)
    return base



def analyze_code(code_content, prompt_template, github_username="", repo_name="", branch_name="main", repo_file_path=""):

    #chunks = split_code_to_chunks(code_content)
    chunks = split_code_to_chunks_with_line_numbers(code_content)


    encoder = tiktoken.encoding_for_model("gpt-4o")

    # for i, chunk in enumerate(chunks):
    #     code_with_lines = add_line_numbers(chunk)
    #     token_count = len(encoder.encode(chunk))
    #     print(f"Chunk {i+1} size in tokens: {token_count}")
    #     print(code_with_lines)

    for i, (start_line, chunk_text) in enumerate(chunks):
        token_count = len(encoder.encode(chunk_text))
        print(f"Chunk {i+1} size in tokens: {token_count}")
        #print(chunk_text)


        prompt = f"{prompt_template}\nAnalyze the following code. Each line is prefixed with a line number for reference:\n\n{chunk_text}"

        for retry_count in range(4):
            try:
                print(f"📤 Sending chunk {i+1}/{len(chunks)}")
                response = client.chat.completions.create(
                    model=MODEL,
                    messages=[{"role": "user", "content": prompt}],
                    temperature=0.2,
                    top_p=0.1,
                    max_tokens=8192
                )

                content = response.choices[0].message.content
                chunk_result = extract_json_from_response(content)

             

                if not isinstance(chunk_result, dict):
                    print(f"⚠️ Skipping chunk {i+1}: Invalid JSON structure")
                    continue  # Skip this chunk safely
                
                print("check_result-----")
                print(chunk_result)
                chunk_result["file_path"] = repo_file_path

                # 🚨 SEND TO DB IMMEDIATELY
                categorize_and_save(
                    chunk_result,
                    github_username=github_username,
                    repo_name=repo_name,
                    branch_name=branch_name
                )

                time.sleep(3)
                break  # success, exit retry

            except Exception as e:
                if "429" in str(e) or "rate limit" in str(e).lower():
                    wait = 3 * (retry_count + 1)
                    print(f"⚠️ Rate limit. Retrying after {wait}s")
                    time.sleep(wait)
                else:
                    print(f"❌ Error in chunk {i+1}: {e}")
                    break  # Don't continue retrying on unknown errors

    return {"status": "chunks_processed"}


def categorize_and_save(data, github_username, repo_name, branch_name="main", email=EMAIL, platform="github"):

    #result = data["result"]
   
    result = data.get("result", data)
    


    #repo_file_path = data["file_path"]  # e.g., "src/app.js"
    repo_file_path = data.get("file_path", "")
    github_style_path = f"{github_username}/{repo_name}/blob/{branch_name}/{repo_file_path}"

    created_at = datetime.now()
    risk_analyzer = RiskAnalyzer()


    def generate_mongodb_id(repo_name, line_number, created_at):
        """Generate MongoDB-style alphanumeric ID (24 characters)"""
        # Create a base string from repo name, line number, and timestamp
        base_string = f"{repo_name}_{line_number}_{created_at.timestamp()}"
        
        # Generate 24-character alphanumeric string similar to MongoDB ObjectId
        alphabet = string.ascii_lowercase + string.digits
        random_part = ''.join(secrets.choice(alphabet) for _ in range(16))
        
        # Combine with some meaningful parts to create 24-char ID
        timestamp_hex = format(int(created_at.timestamp()), '08x')
        repo_hash = format(abs(hash(repo_name)) % (10**8), '06x')
        
        # Ensure exactly 24 characters like MongoDB ObjectId
        mongodb_id = f"{timestamp_hex}{repo_hash}{random_part}"[:24]
        
        return mongodb_id   


    def normalize_issue(issue, category):
        if not isinstance(issue, dict):
            return None

        def b64(s):
            if isinstance(s, str):
                return base64.b64encode(s.encode("utf-8")).decode("utf-8")
            return s


        
        def handle_array_field(field_data):
            if isinstance(field_data, list):
                return json.dumps(field_data)
            return field_data

        # Generate MongoDB-style alphanumeric ID
        line_num = issue.get("line_number", 0)
        mongodb_beacon_id = generate_mongodb_id(repo_name, line_num, created_at)    

        risk_analysis = risk_analyzer.analyze_issue_risk(issue)   
        # ai_severity = issue.get("severity", "Medium")
        # risk_level = risk_analysis["risk_level"]
        # severity_order = {"Info":0,"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
        # #final_severity = ai_severity if severity_order[ai_severity] >= severity_order[risk_level] else risk_level 
        # final_severity = ai_severity if ai_level >= risk_level_num else risk_level

        ai_severity = issue.get("severity", "Medium")
        risk_level = risk_analysis["risk_level"]
    
        # FIX: Always use the HIGHEST severity
        severity_order = {"Info": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
        ai_level = severity_order.get(ai_severity, 1)
        risk_level_num = severity_order.get(risk_level, 1)
    
        # Use whichever is higher
        final_severity = ai_severity if ai_level <= risk_level_num else risk_level


        base_issue = {
            "username": github_username,
            "email": email,
            "platform": platform,
            "repo_name": repo_name,
            "file_path": repo_file_path,
            "line_number": issue.get("line_number"),
            "vulnerability_type": issue.get("vulnerability_type") or issue.get("issue") or issue.get("issue_type"),
            "cwe": issue.get("cwe", "N/A"),
            "cve": issue.get("cve", ""),
            "severity": final_severity,
            "risk_score": risk_analysis["risk_score"],
            "risk_level": risk_analysis["risk_level"],
            "short_description": issue.get("description") or issue.get("short_description", ""),
            "suggested_fix": issue.get("suggested_fix", "Review the code and apply necessary validation/sanitization."),
            "created_at": created_at,
            "bad_practice": (issue.get("bad_practice", "")) if category in ["smelly_code", "malicious_code"] else None,
            "good_practice": issue.get("good_practice", "") if category in ["smelly_code", "malicious_code"] else None,
            "issueId": issue.get("issue_id") or issue.get("id") or mongodb_beacon_id,  # if available
            "branch": branch_name,

            # NEW FIELDS with default NULL values

            "owasp_2017": issue.get("owasp_2017"),
            "owasp_2021": issue.get("owasp_2021"),
            "reproduction_steps": handle_array_field(issue.get("reproduction_steps")),
            "medium_vapt_summary": issue.get("medium_vapt_summary"),
            "impact": handle_array_field(issue.get("impact")),
            "remediation": handle_array_field(issue.get("remediation")),
            "reference": handle_array_field(issue.get("references"))  # Note: 'references' in JSON vs 'reference' in DB


        }
        # if category == "owasp_security":
        #     base_issue["bad_practice"] = (issue.get("vulnerable_code", ""))
        #     base_issue["good_practice"] = issue.get("patched_code", "")

        # if category in ["smelly_code", "malicious_code"]:
        #     base_issue["bad_practice"] = (issue.get("bad_practice", ""))
        #     base_issue["good_practice"] = issue.get("good_practice", "")
        # Handle category-specific field mappings
        if category == "owasp_security":
            base_issue["bad_practice"] = (issue.get("vulnerable_code", ""))
            base_issue["good_practice"] = issue.get("patched_code", "")
            # Ensure VAPT fields are properly handled for owasp_security
            if not base_issue["reproduction_steps"]:
                base_issue["reproduction_steps"] = json.dumps([])
            if not base_issue["impact"]:
                base_issue["impact"] = json.dumps([])
            if not base_issue["remediation"]:
                base_issue["remediation"] = json.dumps([])
            if not base_issue["reference"]:
                base_issue["reference"] = json.dumps([])

        if category in ["smelly_code", "malicious_code"]:
            base_issue["bad_practice"] = (issue.get("bad_practice", ""))
            base_issue["good_practice"] = issue.get("good_practice", "")


        return base_issue

    db = get_db_connection()
    cursor = db.cursor()
    try:
        for category in CATEGORIES:
            section = result.get(category)
            if not section:
                continue

            table_name = CATEGORY_TABLE_MAP[category]
            issues = []

            if isinstance(section, dict):
                for _, issue_list in section.items():
                    for i in issue_list:
                        normalized = normalize_issue(i, category)
                        if normalized:
                            issues.append(normalized)
            elif isinstance(section, list):
                for i in section:
                    normalized = normalize_issue(i, category)
                    if normalized:
                        issues.append(normalized)

            if not issues:
                continue

            # Construct the INSERT query
            keys = issues[0].keys()
            fields = ", ".join(keys)
            placeholders = ", ".join(["%s"] * len(keys))
            insert_query = f"INSERT INTO {table_name} ({fields}) VALUES ({placeholders})"

            for issue in issues:
                cursor.execute(insert_query, list(issue.values()))

            print(f"✅ Inserted {len(issues)} issues into {table_name}")

        db.commit()
    except Exception as e:
        db.rollback()
        print(f"❌ Error inserting issues: {e}")
    finally:
        cursor.close()
        db.close()

  

def get_valid_branch(username, repo, token, preferred=None):
    branches = ["main", "master"]
    if preferred and preferred not in branches:
        branches.insert(0, preferred)
    for branch in branches:
        try:
            url = f"https://api.github.com/repos/{username}/{repo}/branches/{branch}"
            headers = {"Authorization": f"Bearer {token}"}
            response = requests.get(url, headers=headers, timeout=15)
            if response.status_code == 200:
                return branch
        except requests.RequestException as e:
            print(f"⚠️ Branch check failed: {e}")
    raise Exception("❌ No valid branch found")

# def get_repo_files(username, repo, branch, token):
#     url = f"https://api.github.com/repos/{username}/{repo}/git/trees/{branch}?recursive=1"
#     headers = {"Authorization": f"Bearer {token}"}
#     response = requests.get(url, headers=headers, timeout=20)
#     response.raise_for_status()
#     tree = response.json().get("tree", [])
#     return [item for item in tree if item["type"] == "blob" and Path(item["path"]).suffix in ALLOWED_EXTENSIONS]

"""
def get_repo_files(username, repo, branch, token):
    url = f"https://api.github.com/repos/{username}/{repo}/git/trees/{branch}?recursive=1"
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(url, headers=headers, timeout=20)
    response.raise_for_status()
    tree = response.json().get("tree", [])

    filtered_files = []
    for item in tree:
        if item["type"] != "blob":
            continue

        file_path = item["path"]
        suffix = Path(file_path).suffix
        filename = Path(file_path).name

        # Only allow .json, .txt, .xml if they're special dependency files
        if suffix in {'.json', '.txt', '.xml'}:
            if filename in SPECIAL_FILES:
                filtered_files.append(item)
        elif suffix in ALLOWED_EXTENSIONS:
            filtered_files.append(item)

    return filtered_files
"""



def get_repo_files(username, repo, branch, token):
    url = f"https://api.github.com/repos/{username}/{repo}/git/trees/{branch}?recursive=1"
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(url, headers=headers, timeout=20)
    response.raise_for_status()
    tree = response.json().get("tree", [])

    filtered_files = []
    for item in tree:
        if item.get("type") != "blob":
            continue

        file_path = item.get("path", "")
        suffix = Path(file_path).suffix.lower()     # normalized extension (e.g. ".js")
        filename = Path(file_path).name
        lower_path = file_path.lower()
        lower_name = filename.lower()

        # 1) Only allow special dependency files if they are in SPECIAL_FILES
        if suffix in {'.json', '.txt', '.xml'}:
            if filename in SPECIAL_FILES:
                filtered_files.append(item)
            # else: skip other .json/.txt/.xml files
            continue

        # 2) Only consider files with allowed extensions
        if suffix not in ALLOWED_EXTENSIONS:
            continue

        # 3) Exclude files that match any EXCLUDED_PATTERNS (unless they are SPECIAL_FILES)
        excluded = False
        for pat in EXCLUDED_PATTERNS:
            p = pat.lower()
            # If pattern contains a slash treat it as a path pattern, otherwise match filename and path
            if "/" in p:
                if fnmatch.fnmatch(lower_path, p):
                    excluded = True
                    break
            else:
                if fnmatch.fnmatch(lower_name, p) or fnmatch.fnmatch(lower_path, p):
                    excluded = True
                    break

        if excluded:
            # skip excluded file
            continue

        # 4) Passed all checks -> include
        filtered_files.append(item)

    return filtered_files


def download_file(username, repo, path, token, branch="main"):
    url = f"https://api.github.com/repos/{username}/{repo}/contents/{path}?ref={branch}"
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(url, headers=headers, timeout=20)
    response.raise_for_status()
    content = base64.b64decode(response.json()["content"]).decode("utf-8", errors="ignore")
    return content

# def get_access_token(username):
#     url = f"{SITE_URL}/getToken"
#     response = requests.post(url, json={"username": username}, headers={"Content-Type": "application/json"}, timeout=10)
#     response.raise_for_status()
#     return response.json()['data']['client_access_token']

# def get_access_token(username):
#     url = f"{SITE_URL}/getToken"
#     response = requests.post(
#         url,
#         json={"username": username},
#         headers={"Content-Type": "application/json"},
#         timeout=10
#     )
#     response.raise_for_status()
#     data = response.json()['data']
#     return data['client_access_token'], data.get('email', '')

# def get_access_token(username):
#     global EMAIL, TOKEN  # use global to modify them

#     url = f"{SITE_URL}/getToken"
#     response = requests.post(
#         url,
#         json={"username": username,"platform":"github"},
#         headers={"Content-Type": "application/json"},
#         timeout=10
#     )
#     response.raise_for_status()
#     data = response.json().get('data', {})

#     TOKEN = data.get('client_access_token', '')
#     EMAIL = data.get('email', '')
    

#     return TOKEN




def get_access_token(username, platform="github"):
    """
    Fetch access token for a given username & platform from SITE_URL/getToken
    Retries on 500/timeout/network errors up to MAX_RETRIES times.
    """
    global EMAIL, TOKEN
    url = f"{SITE_URL}/getToken"
    payload = {"username": username, "platform": platform}
    headers = {"Content-Type": "application/json"}

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            response = requests.post(url, json=payload, headers=headers, timeout=10)
            print(f"[get_access_token] Attempt {attempt}, status={response.status_code}")

            # Retry on server errors
            if response.status_code >= 500:
                raise requests.exceptions.HTTPError(f"Server error {response.status_code}: {response.text}")

            response.raise_for_status()
            data = response.json().get("data", {})

            TOKEN = data.get("client_access_token", "")
            EMAIL = data.get("email", "")

            if not TOKEN:
                raise ValueError("No client_access_token in response")

            return TOKEN
        except Exception as e:
            print(f"⚠️ get_access_token error (attempt {attempt}): {e}")
            if attempt == MAX_RETRIES:
                raise  # give up after retries
            time.sleep(RETRY_DELAY * attempt)




def detect_ecosystem(filename):
    if filename == "package.json":
        return "npm"
    elif filename == "requirements.txt":
        return "PyPI"
    elif filename == "pom.xml":
        return "Maven"
    else:
        return None




##--------XXXXX---------

from datetime import datetime

def save_sca_info(vulns, username, repo, branch, file_path, version,vuln_pack, email=EMAIL, platform="github"):
    conn = get_db_connection()
    cursor = conn.cursor()

    for vuln in vulns:
        # CVE and CWE
        cve = next((a for a in vuln.get("aliases", []) if a.startswith("CVE-")), vuln.get("id"))
        cwe = ", ".join(vuln.get("database_specific", {}).get("cwe_ids", []))
        severity = vuln.get("database_specific", {}).get("severity", "Unknown")

        # Descriptions
        description =  vuln.get("details", "")
        vuln_type= vuln.get("summary") 

        # Fix version
        fix_version = next(
            (e.get("fixed") for r in vuln.get("affected", [{}])[0].get("ranges", [])
             for e in r.get("events", []) if "fixed" in e),
            "Upgrade Recommended"
        )

        # Advice URLs
        advice_urls = "\n".join(ref.get("url") for ref in vuln.get("references", []) if "url" in ref)

        # Suggested fix message
        suggested_fix = f"Upgrade to version {fix_version}.\n\nReferences:\n{advice_urls}"

        # Affected version
        affected_versions = ", ".join(vuln.get("affected", [{}])[0].get("versions", [])) or version

        # Insert into DB
        cursor.execute("""
            INSERT INTO sca_info (
                username, email, platform, repo_name, file_path, line_number,
                vulnerability_type, cwe, cve, severity, short_description,
                suggested_fix, vulnerable_code, patched_code,
                bad_practice, good_practice, issueId, branch, affected_version, vulnerable_package,
                created_at
            ) VALUES (%s, %s, %s, %s, %s, NULL,
                      %s, %s, %s, %s, %s,
                      %s, NULL, NULL,
                      NULL, NULL, %s, %s, %s, %s,
                      NOW())
        """, (
            username, email, platform, repo, file_path,
            vuln_type, cwe, cve, severity, description,
            suggested_fix, vuln.get("id"), branch, affected_versions, vuln_pack
        ))

    conn.commit()
    cursor.close()
    conn.close()













"""
def run_dependency_scan(file_path, file_content, username, repo, branch, email=None, platform="github"):
    dependencies = []
    ecosystem = detect_ecosystem(file_path)

    if not ecosystem:
        print(f"⛔ Unsupported file type for dependency scanning: {file_path}")
        return

    try:
        if ecosystem == "npm":
            package_data = json.loads(file_content)
            deps = package_data.get("dependencies", {})
            dev_deps = package_data.get("devDependencies", {})
            dependencies.extend([{"name": k, "version": v} for k, v in {**deps, **dev_deps}.items()])

        elif ecosystem == "PyPI":
            lines = file_content.splitlines()
            for line in lines:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "==" in line:
                    name, version = line.split("==", 1)
                    dependencies.append({"name": name.strip(), "version": version.strip()})
                else:
                    dependencies.append({"name": line.strip()})

        elif ecosystem == "Maven":
            print(f"⚠️ Skipping pom.xml: XML parsing not implemented")
            return

    except Exception as e:
        print(f"❌ Error parsing dependencies in {file_path}: {e}")
        return

    if not dependencies:
        print(f"⚠️ No dependencies found in {file_path}")
        return

    print(f"🔍 Scanning {len(dependencies)} dependencies from {file_path}")

    API_URL = "https://api.osv.dev/v1/query"
    all_vulnerabilities = []

    for dep in dependencies:
        name = dep.get("name")
        version = dep.get("version")

        query = {
            "package": {
                "name": name,
                "ecosystem": ecosystem
            }
        }

        if version:
            query["version"] = version

        try:
            response = requests.post(API_URL, json=query)
            if response.status_code == 200:
                result = response.json()
                vulns = result.get("vulns", [])
                if vulns:
                    print(f"⚠️ {name}@{version} has {len(vulns)} vulnerabilities")
                    printf(vulns)
                    all_vulnerabilities.extend(vulns)
            else:
                print(f"⚠️ API error for {name}: {response.status_code}")
        except Exception as e:
            print(f"❌ Exception for {name}: {e}")

    if all_vulnerabilities:
        save_sca_info(
            vulnerabilities=all_vulnerabilities,
            username=username,
            repo_name=repo,
            file_path=file_path,
            branch=branch,
            email=email,
            platform=platform
        )
        print(f"✅ Vulnerabilities saved for {file_path}")
    else:
        print(f"✅ No vulnerabilities found in {file_path}")
"""
"""
def run_dependency_scan(file_path, file_content, username, repo, branch, email=None, platform="github"):
    from pathlib import Path
    file_name = Path(file_path).name
    print(f"🔎 Detecting ecosystem for file: {file_name}-------X----")
    
    ecosystem = detect_ecosystem(file_path)
    
    if not ecosystem:
        print(f"⛔ Unsupported file type for dependency scanning: {file_content}")
        return

    print(f"🔍 Running SCA for: {file_name}")

    dependencies = extract_dependencies(file_name, file_content)
    if not dependencies:
        print(f"⚠️ No dependencies found in {file_name}")
        return

    for dep in dependencies:
        package_name = dep.get("name")
        version = dep.get("version")

        if not package_name or not version:
            continue

        payload = {
            "package": {
                "name": package_name,
                "ecosystem": ecosystem
            },
            "version": version
        }

        try:
            response = requests.post(OSV_API_URL, json=payload, timeout=10)
            response.raise_for_status()
            data = response.json()
            print(data)
            

            if "vulns" in data:
                
                save_sca_info(data["vulns"], username, repo, branch, file_path, version,email, platform="github")
        except Exception as e:
            print(f"❌ Error querying OSV for {package_name}@{version}: {e}")
"""


MAX_RETRIES = 5
RETRY_DELAY = 3  # seconds

def query_osv_with_retry(payload):
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            #print(payload)
            response = requests.post(OSV_API_URL, json=payload, timeout=15)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"❌ Attempt {attempt} failed: {e}")
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_DELAY * attempt)
            else:
                with open("failed_osv_requests.log", "a") as f:
                    f.write(f"{payload['package']['name']}@{payload['version']}\n")
                print(f"❌ Skipping {payload['package']['name']}@{payload['version']} after {MAX_RETRIES} retries.")
                return None




def run_dependency_scan(file_path, file_content, username, repo, branch, email, platform="github"):
    from pathlib import Path
    import requests

    file_name = Path(file_path).name
    #print(f"🔎 email: {email}-------X----")

    print(f"🔎 Detecting ecosystem for file: {file_name}-------X----")

    ecosystem = detect_ecosystem(file_name)

    if not ecosystem:
        print(f"⛔ Unsupported file type for dependency scanning: {file_content}")
        return

    print(f"🔍 Running SCA for: {file_name}")

    dependencies = extract_dependencies(file_name, file_content)
    if not dependencies:
        print(f"⚠️ No dependencies found in {file_name}")
        return

    for dep in dependencies:
        package_name = dep.get("name")
        version = dep.get("version")

        if not package_name or not version:
            continue

        payload = {
            "package": {
                "name": package_name,
                "ecosystem": ecosystem
            },
            "version": version
        }

        try:
            # response = requests.post(OSV_API_URL, json=payload, timeout=10)
            # response.raise_for_status()
            # data = response.json()
           
            #print(payload)
            data = query_osv_with_retry(payload)
            vuln_pack = f"{package_name}@{version}"
            #print(f"🔎 email: {email}-------X----")
            

            print(data)

            if "vulns" in data:
                # ✅ Pass email and platform to save_sca_info
                save_sca_info(
                    vulns=data["vulns"],
                    username=username,
                    repo=repo,
                    branch=branch,
                    file_path=file_path,
                    version=version,
                    email=EMAIL,
                    platform=platform,
                    vuln_pack=vuln_pack
                )
        except Exception as e:
            print(f"❌ Error querying OSV for {package_name}@{version}: {e}")



def extract_dependencies(filename, content):
    try:
        if filename == "package.json":
            data = json.loads(content)
            deps = data.get("dependencies", {})
            return [{"name": name, "version": version} for name, version in deps.items()]

        elif filename == "requirements.txt":
            lines = content.strip().split("\n")
            result = []
            for line in lines:
                if "==" in line:
                    name, version = line.split("==")
                    result.append({"name": name.strip(), "version": version.strip()})
            return result

        elif filename == "pom.xml":
            root = ET.fromstring(content)
            ns = {'m': 'http://maven.apache.org/POM/4.0.0'}
            deps = root.findall(".//m:dependency", ns)
            result = []
            for dep in deps:
                group = dep.find("m:groupId", ns).text
                artifact = dep.find("m:artifactId", ns).text
                version = dep.find("m:version", ns).text
                result.append({"name": f"{group}:{artifact}", "version": version})
            return result

    except Exception as e:
        print(f"❌ Failed to parse dependencies in {filename}: {e}")
        return []



##--------XXXXX---------##--------XXXXX---------

def process_file(file, username, repo, branch, token, prompt_template,email=EMAIL,max_retries=2):
    path = file["path"]
    for attempt in range(1, max_retries + 1):
        try:
            print(f"📥 Downloading: {path} (Attempt {attempt})")
            print(email)
            content = download_file(username, repo, path, token, branch)

            # ✅ Run Dependency Scan First (for known files)
            if os.path.basename(path) in ["package.json", "requirements.txt", "pom.xml"]:
                print(f"🔍 Running SCA for: {path}")
                run_dependency_scan(path,content, username, repo, branch,email=email,platform="github")
                
                continue
            

            print(f"🤖 Analyzing: {path}")
            analysis = analyze_code(content,prompt_template,github_username=username,repo_name=repo,branch_name=branch,repo_file_path=path)


            if not isinstance(analysis, dict):
                print(f"❌ Skipping {path}: Invalid result")
                return

            analysis["file_path"] = path
            print(f"💾 Saving analysis results for: {path}")
            categorize_and_save(analysis, github_username=username, repo_name=repo, branch_name=branch)

            time.sleep(random.uniform(5, 10))
            return f"✅ Processed: {path}"

        except Exception as e:
            print(f"❌ Error processing {path} (Attempt {attempt}): {str(e)}")
            if attempt == max_retries:
                return f"❌ Failed after {max_retries} attempts: {path}"
            time.sleep(random.uniform(5, 10))


def update_scan_status(scan_id, status="completed"):
    """
    Update the scan_status in sastcode_schema.scan_status after SCA scan finishes.
    
    Args:
        scan_id (int): The ID of the scan to update.
        status (str): Status to set, e.g., 'completed' or 'failed'.
    """
    conn = get_db_connection()  # make sure this connects to the right DB
    cursor = conn.cursor()
    try:
        cursor.execute("""
            UPDATE sastcode_schema.scan_status
            SET status = %s, finished_at = NOW()
            WHERE scan_id = %s
        """, (status, scan_id))
        conn.commit()
        print(f"✅ scan_status updated to '{status}' for scan_id {scan_id}")
    except Exception as e:
        conn.rollback()
        print(f"❌ Error updating scan_status: {e}")
    finally:
        cursor.close()
        conn.close()


def main():
    if len(sys.argv) < 3:
        print("Usage: python scanner.py <username> <repo> [branch]")
        sys.exit(1)

    username, repo = sys.argv[1], sys.argv[2]
    branch = sys.argv[3] if len(sys.argv) > 3 else None
    scan_id = sys.argv[5] if len(sys.argv) > 5 else None

    print(f"🔍 Analyzing {username}/{repo}...")

    try:
        token = get_access_token(username)
        email=EMAIL
        valid_branch = get_valid_branch(username, repo, token, preferred=branch)
        print(f"📦 Using branch: {valid_branch}")
        files = get_repo_files(username, repo, valid_branch, token)
        if not files:
            print("⚠️ No valid files found.")
            return

        prompt_template = load_prompt_template()
        max_threads = min(4, len(files))  # Limit threads to avoid TPM spike
        print(f"🚀 Processing with {max_threads} threads...")

        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = [
                executor.submit(process_file, file, username, repo, valid_branch, token, prompt_template,email)
                for file in files
            ]
            for future in as_completed(futures):
                print(future.result())

        print("✅ All files processed.")
        if scan_id:
            update_scan_status(scan_id, status="completed")
        else:
            print("⚠️ No scan_id provided, cannot update scan_status.")

    except Exception as e:
        print(f"❌ Fatal error: {e}")
        if scan_id:
            update_scan_status(scan_id, status="failed")

if __name__ == "__main__":
    main()
