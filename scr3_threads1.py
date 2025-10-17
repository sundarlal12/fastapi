# import sys
# import os
# import requests
# import base64
# import mysql.connector  
# from dotenv import load_dotenv
# from concurrent.futures import ThreadPoolExecutor, as_completed
# import json
# from datetime import datetime
# import yaml
# import re
# from pathlib import Path
# import openai
# import time
# import random

# # Load .env variables
# load_dotenv()
# SITE_URL = os.getenv("SITE_URL")
# OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
# MODEL = "gpt-4o"
# client = openai.OpenAI(api_key=OPENAI_API_KEY)

# DB_CONFIG = {
#     "user": os.getenv("DB_USERNAME"),
#     "password": os.getenv("DB_PASSWORD"),
#     "host": os.getenv("DB_HOST"),
#     "database": os.getenv("DB_NAME")
# }

# CATEGORIES = [
#     "dead_code", "docstring", "malicious_code",
#     "owasp_security", "secrets", "smelly_code"
# ]

# CATEGORY_TABLE_MAP = {
#     "dead_code": "dead_code_info",
#     "docstring": "docstring_info",
#     "malicious_code": "malicious_code_info",
#     "owasp_security": "owasp_security_info",
#     "secrets": "secrets_info",
#     "smelly_code": "smelly_code_info"
# }

# ALLOWED_EXTENSIONS = {
#     '.py', '.js', '.java', '.cpp', '.php', '.html', '.ts', '.rb', '.go', '.c', '.rs'
# }

# def get_db_connection():
#     return mysql.connector.connect(**DB_CONFIG)

# def load_prompt_template(path="review_prompt.yml"):
#     with open(path, "r") as file:
#         yml = yaml.safe_load(file)
#         return yml["review_template"]

# def extract_json_from_response(text):
#     try:
#         return json.loads(text)
#     except json.JSONDecodeError:
#         match = re.search(r'{[\s\S]+}', text)
#         if match:
#             try:
#                 return json.loads(match.group())
#             except json.JSONDecodeError as e:
#                 print(f"⚠️ JSON decoding failed after regex extract: {e}")
#                 return {"error": "Malformed JSON after regex extract"}
#         return {"error": "No valid JSON found in output"}

# def add_line_numbers(code):
#     return "\n".join(f"{i+1}: {line}" for i, line in enumerate(code.splitlines()))

# def split_code_to_chunks(code, max_tokens=8000):
#     lines = code.splitlines()
#     chunks, chunk, token_estimate = [], [], 0
#     for line in lines:
#         token_estimate += len(line.split())  # rough token estimate
#         chunk.append(line)
#         if token_estimate >= max_tokens:
#             chunks.append("\n".join(chunk))
#             chunk, token_estimate = [], 0
#     if chunk:
#         chunks.append("\n".join(chunk))
#     return chunks

# def merge_results(base, new):
#     if not isinstance(base, dict):
#         base = {}
#     if not isinstance(new, dict):
#         return base
#     for key, val in new.items():
#         if key not in base:
#             base[key] = val
#         elif isinstance(val, list) and isinstance(base.get(key), list):
#             base[key].extend(val)
#         elif isinstance(val, dict) and isinstance(base.get(key), dict):
#             base[key] = merge_results(base[key], val)
#     return base

# def analyze_code(code_content, prompt_template):
#     chunks = split_code_to_chunks(code_content)
#     full_result = {}
#     for i, chunk in enumerate(chunks):
#         code_with_lines = add_line_numbers(chunk)
#         prompt = f"{prompt_template}\nAnalyze the following code. Each line is prefixed with a line number:\n\n{code_with_lines}"
#         try:
#             response = client.chat.completions.create(
#                 model=MODEL,
#                 messages=[{"role": "user", "content": prompt}],
#                 temperature=0.2,
#                 top_p=0.1,
#                 max_tokens=8192
#             )
#             chunk_result = extract_json_from_response(response.choices[0].message.content)
#             full_result = merge_results(full_result, chunk_result)

#             if i < len(chunks) - 1:
#                 print(f"⏳ Throttling... waiting 60s before next chunk")
#                 time.sleep(60)

#         except Exception as e:
#             return {"error": str(e)}

#     return full_result

# def categorize_and_save(data, github_username, repo_name, branch_name="main", email="", platform="GitHub"):
#     result = data.get("result", data)
#     repo_file_path = data.get("file_path", "")
#     db = get_db_connection()
#     cursor = db.cursor()

#     try:
#         for category in CATEGORIES:
#             section = result.get(category)
#             if not section:
#                 continue

#             table_name = CATEGORY_TABLE_MAP[category]
#             issues = []

#             def normalize_issue(issue, category):
#                 if not isinstance(issue, dict):
#                     return None
#                 base_issue = {
#                     "username": github_username,
#                     "email": email,
#                     "platform": platform,
#                     "repo_name": repo_name,
#                     "file_path": repo_file_path,
#                     "line_number": issue.get("line_number"),
#                     "vulnerability_type": issue.get("vulnerability_type") or issue.get("issue") or issue.get("issue_type"),
#                     "cwe": issue.get("cwe", "N/A"),
#                     "cve": issue.get("cve", ""),
#                     "severity": issue.get("severity", "Medium"),
#                     "short_description": issue.get("description") or issue.get("short_description", ""),
#                     "suggested_fix": issue.get("suggested_fix", "Review the code and apply necessary validation/sanitization."),
#                     "created_at": datetime.now(),
#                     "bad_practice": issue.get("bad_practice", "") if category in ["smelly_code", "malicious_code"] else None,
#                     "good_practice": issue.get("good_practice", "") if category in ["smelly_code", "malicious_code"] else None,
#                     "issueId": issue.get("issue_id") or issue.get("id") or "",
#                     "branch": branch_name
#                 }
#                 if category == "owasp_security":
#                     base_issue["bad_practice"] = issue.get("vulnerable_code", "")
#                     base_issue["good_practice"] = issue.get("patched_code", "")
#                 return base_issue

#             if isinstance(section, dict):
#                 for _, issue_list in section.items():
#                     for i in issue_list:
#                         norm = normalize_issue(i, category)
#                         if norm:
#                             issues.append(norm)
#             elif isinstance(section, list):
#                 for i in section:
#                     norm = normalize_issue(i, category)
#                     if norm:
#                         issues.append(norm)

#             if not issues:
#                 continue

#             keys = issues[0].keys()
#             fields = ", ".join(keys)
#             placeholders = ", ".join(["%s"] * len(keys))
#             insert_query = f"INSERT INTO {table_name} ({fields}) VALUES ({placeholders})"

#             for issue in issues:
#                 cursor.execute(insert_query, list(issue.values()))
#             print(f"✅ Inserted {len(issues)} into {table_name}")
#         db.commit()

#     except Exception as e:
#         db.rollback()
#         print(f"❌ Error inserting: {e}")
#     finally:
#         cursor.close()
#         db.close()

# def get_valid_branch(username, repo, token, preferred=None):
#     branches = ["main", "master"]
#     if preferred and preferred not in branches:
#         branches.insert(0, preferred)
#     for branch in branches:
#         url = f"https://api.github.com/repos/{username}/{repo}/branches/{branch}"
#         headers = {"Authorization": f"Bearer {token}"}
#         response = requests.get(url, headers=headers)
#         if response.status_code == 200:
#             return branch
#     raise Exception("❌ No valid branch found")

# def get_repo_files(username, repo, branch, token):
#     url = f"https://api.github.com/repos/{username}/{repo}/git/trees/{branch}?recursive=1"
#     headers = {"Authorization": f"Bearer {token}"}
#     response = requests.get(url, headers=headers)
#     response.raise_for_status()
#     tree = response.json().get("tree", [])
#     return [item for item in tree if item["type"] == "blob" and Path(item["path"]).suffix in ALLOWED_EXTENSIONS]

# def download_file(username, repo, path, token, branch="main"):
#     url = f"https://api.github.com/repos/{username}/{repo}/contents/{path}?ref={branch}"
#     headers = {"Authorization": f"Bearer {token}"}
#     response = requests.get(url, headers=headers)
#     response.raise_for_status()
#     content = base64.b64decode(response.json()["content"]).decode("utf-8", errors="ignore")
#     return content

# def get_access_token(username):
#     url = f"{SITE_URL}/getToken"
#     response = requests.post(url, json={"username": username}, headers={"Content-Type": "application/json"})
#     response.raise_for_status()
#     return response.json()['data']['client_access_token']

# def process_file(file, username, repo, branch, token, prompt_template):
#     try:
#         time.sleep(random.uniform(50, 70))  # throttle to stay under OpenAI limits

#         path = file["path"]
#         print(f"📥 Downloading: {path}")
#         content = download_file(username, repo, path, token, branch)

#         print(f"🤖 Analyzing: {path}")
#         analysis = analyze_code(content, prompt_template)

#         if not isinstance(analysis, dict):
#             print(f"❌ Skipping {path}: Invalid result")
#             return

#         analysis["file_path"] = path
#         print(f"💾 Saving analysis results for: {path}")
#         categorize_and_save(analysis, github_username=username, repo_name=repo, branch_name=branch)
#         return f"✅ Processed: {path}"
#     except Exception as e:
#         return f"❌ Error processing {file['path']}: {str(e)}"

# def main():
#     if len(sys.argv) < 3:
#         print("Usage: python scanner.py <username> <repo> [branch]")
#         sys.exit(1)

#     username, repo = sys.argv[1], sys.argv[2]
#     branch = sys.argv[3] if len(sys.argv) > 3 else None
#     print(f"🔍 Analyzing {username}/{repo}...")

#     try:
#         token = get_access_token(username)
#         valid_branch = get_valid_branch(username, repo, token, preferred=branch)
#         print(f"📦 Using branch: {valid_branch}")
#         files = get_repo_files(username, repo, valid_branch, token)
#         if not files:
#             print("⚠️ No valid files found.")
#             return

#         prompt_template = load_prompt_template()
#         max_threads = min(10, len(files))
#         print(f"🚀 Processing with {max_threads} threads...")

#         with ThreadPoolExecutor(max_workers=max_threads) as executor:
#             futures = [
#                 executor.submit(process_file, file, username, repo, valid_branch, token, prompt_template)
#                 for file in files
#             ]
#             for future in as_completed(futures):
#                 print(future.result())

#         print("✅ All files processed.")
#     except Exception as e:
#         print(f"❌ Fatal error: {e}")

# if __name__ == "__main__":
#     main()





# scanner.py
import tiktoken
import sys
import os
import base64
import requests
import base64
import mysql.connector
import psycopg2
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
from datetime import datetime
import yaml
import regex as re
from pathlib import Path
import openai
import time
import random

# Load .env variables
load_dotenv()
SITE_URL = os.getenv("SITE_URL")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
MODEL = "gpt-4o"
client = openai.OpenAI(api_key=OPENAI_API_KEY)

DB_CONFIG = {
    "user": os.getenv("DB_USERNAME"),
    "password": os.getenv("DB_PASSWORD"),
    "host": os.getenv("DB_HOST"),
    "database": os.getenv("DB_NAME"),
    "port": int(os.getenv("DB_PORT", "25060")) 
}

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
    '.py', '.js', '.java', '.cpp', '.php', '.html', '.ts', '.rb', '.go', '.c', '.rs'
}

def get_db_connection():
    return mysql.connector.connect(**DB_CONFIG)

def load_prompt_template(path="review_prompt.yml"):
    with open(path, "r") as file:
        yml = yaml.safe_load(file)
        return yml["review_template"]


def fix_hex_strings(s):
    # Fix invalid JSON escape sequences like \x47 to \\x47
    return re.sub(r'(?<!\\)(\\x[0-9a-fA-F]{2})', r'\\\1', s)

def extract_first_json_object(text):
    start = text.find('{')
    if start == -1:
        return None
    stack = []
    for i in range(start, len(text)):
        if text[i] == '{':
            stack.append('{')
        elif text[i] == '}':
            stack.pop()
            if not stack:
                return text[start:i+1]
    return None

"""
def extract_json_from_response(text):
    import json
 

    # Try full parse
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Find JSON objects in the string
    matches = re.findall(r'\{(?:[^{}]|(?R))*\}', text)  # recursive regex for nested JSON

    for match in matches:
        fixed = fix_hex_strings(match)
        try:
            return json.loads(fixed)
        except json.JSONDecodeError:
            continue

    # Last attempt: try fix trailing commas + fix hex then parse
    try:
        json_start = text.find('{')
        if json_start != -1:
            json_part = text[json_start:]
            json_part = re.sub(r',\s*([\]}])', r'\1', json_part)
            json_part = fix_hex_strings(json_part)
            return json.loads(json_part)
    except Exception as e:
        print(f"⚠️ JSON fix failed: {e}")

    print(f"❌ No valid JSON found. Raw:\n{text}")
    return {"error": "Malformed or missing JSON"}
"""

# def extract_json_from_response(text):
#     json_str = extract_first_json_object(text)
#     if not json_str:
#         print("No JSON object found.")
#         return None

#     json_str_fixed = fix_hex_strings(json_str)

#     try:
#         return json.loads(json_str_fixed)
#     except json.JSONDecodeError as e:
#         print("Still failed to parse:", e)
#         return None



"""
import json
import base64

def extract_json_from_response(text):

    print("------")
    print(text)
    print("------")

    def extract_first_json_object(text):
        start = text.find('{')
        if start == -1:
            return None

        brace_count = 0
        end = start
        for i in range(start, len(text)):
            if text[i] == '{':
                brace_count += 1
            elif text[i] == '}':
                brace_count -= 1
                if brace_count == 0:
                    end = i + 1
                    break

        json_str = text[start:end]
        try:
            return json.loads(json_str)
        except json.JSONDecodeError:
            return None

    def encode_bad_practice_recursively(obj):
        if isinstance(obj, dict):
            for key, value in obj.items():
                if key == "bad_practice" and isinstance(value, str):
                    obj[key] = base64.b64encode(value.encode('utf-8')).decode('utf-8')
                else:
                    encode_bad_practice_recursively(value)
        elif isinstance(obj, list):
            for item in obj:
                encode_bad_practice_recursively(item)

    parsed_json = extract_first_json_object(text)
    if parsed_json is None:
        print("❌ No valid JSON found in this chunk.")
        return None

    try:
        encode_bad_practice_recursively(parsed_json)
        return parsed_json
    except Exception as e:
        print("❌ Failed to process JSON:", e)
        return None
"""

import json
import base64

def extract_json_from_response(text):

    print("---x----")
    print(text)
    print("---x----")

    def extract_first_json_object(text):
        start = text.find('{')
        if start == -1:
            return None
        stack = []
        for i in range(start, len(text)):
            if text[i] == '{':
                stack.append('{')
            elif text[i] == '}':
                stack.pop()
                if not stack:
                    try:
                        return json.loads(text[start:i+1])
                    except json.JSONDecodeError:
                        return None
        return None

    # def encode_bad_practice_recursively(obj):
    #     if isinstance(obj, dict):
    #         for key, value in obj.items():
    #             if key == "bad_practice" and isinstance(value, str):
    #                 obj[key] = base64.b64encode(value.encode('utf-8')).decode('utf-8')
    #             else:
    #                 encode_bad_practice_recursively(value)
    #     elif isinstance(obj, list):
    #         for item in obj:
    #             encode_bad_practice_recursively(item)

    def encode_bad_practice_recursively(obj):
        if isinstance(obj, dict):
            for key, value in obj.items():
                if key == "bad_practice" and isinstance(value, str):
                    try:
                        raw_bytes = value.encode('latin1')  # preserve byte structure
                        obj[key] = base64.b64encode(raw_bytes).decode('utf-8')
                    except Exception as e:
                        print(f"⚠️ Failed to encode bad_practice: {e}")
                else:
                    encode_bad_practice_recursively(value)
        elif isinstance(obj, list):
            for item in obj:
                encode_bad_practice_recursively(item)


    parsed_json = extract_first_json_object(text)
    if parsed_json is None:
        print("❌ No valid JSON found in this chunk.")
        return None

    try:
        encode_bad_practice_recursively(parsed_json)
        return parsed_json
    except Exception as e:
        print("❌ Failed to process JSON:", e)
        return None




"""
def extract_json_from_response(text):
    import json
    import re

    # Attempt full load first
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Extract first valid JSON-looking object from string
    matches = re.findall(r'{[\s\S]+?}', text)
    for match in matches:
        try:
            return json.loads(match)
        except json.JSONDecodeError as e:
            continue

    # Attempt to fix common issues like trailing commas or quotes
    try:
        # Find likely start of JSON
        json_start = text.find('{')
        if json_start != -1:
            json_part = text[json_start:]
            # Remove trailing text after closing brace if present
            json_part = re.split(r'}\s*$', json_part, maxsplit=1)[0] + '}'

            # Remove potential extra trailing commas
            json_part = re.sub(r',\s*}', '}', json_part)
            json_part = re.sub(r',\s*]', ']', json_part)

            return json.loads(json_part)
    except Exception as e:
        print(f"⚠️ JSON decoding failed with attempt to fix: {e}")

    print(f"❌ No valid JSON found in output. Raw response:\n{text}")
    return {"error": "Malformed or missing JSON"}
"""
def add_line_numbers(code):
    return "\n".join(f"{i+1}: {line}" for i, line in enumerate(code.splitlines()))



"""
def split_code_to_chunks(code, max_tokens=3500):
    lines = code.splitlines()
    chunks, chunk, token_estimate = [], [], 0
    for line in lines:
        token_estimate += int(len(line.split()) * 1.3)
        chunk.append(line)
        if token_estimate >= max_tokens:
            chunks.append("\n".join(chunk))
            chunk, token_estimate = [], 0
    if chunk:
        chunks.append("\n".join(chunk))
    return chunks
"""
def estimate_tokens(text):
    # Rough estimate: 1 token ~= 4 characters in English
    return int(len(text) / 4)

# def split_code_to_chunks(code, max_tokens=3000):
#     enc = tiktoken.encoding_for_model(MODEL)
#     lines = code.splitlines()
#     chunks, chunk, tokens_in_chunk = [], [], 0
#     for line in lines:
#         line_tokens = len(enc.encode(line))
#         if tokens_in_chunk + line_tokens > max_tokens:
#             chunks.append("\n".join(chunk))
#             chunk, tokens_in_chunk = [], 0
#         chunk.append(line)
#         tokens_in_chunk += line_tokens
#     if chunk:
#         chunks.append("\n".join(chunk))
#     return chunks
import tiktoken

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
"""
def analyze_code(code_content, prompt_template):
    # chunks = split_code_to_chunks(code_content)
    chunks = split_code_to_chunks(code_content, model=MODEL, max_tokens_per_chunk=7168)

    print(f"📤 Sending chunk {i+1}/{len(chunks)} (approx {len(tiktoken.encoding_for_model(MODEL).encode(chunk))} tokens)")

    full_result = {}
    for i, chunk in enumerate(chunks):
        code_with_lines = add_line_numbers(chunk)
        prompt = f"{prompt_template}\nAnalyze the following code. Each line is prefixed with a line number:\n\n{code_with_lines}"
        try:
            response = client.chat.completions.create(
                model=MODEL,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.2,
                top_p=0.1,
                max_tokens=8192
            )
            chunk_result = extract_json_from_response(response.choices[0].message.content)
            full_result = merge_results(full_result, chunk_result)
            if i < len(chunks) - 1:
                delay = random.uniform(30, 60)
                print(f"⏳ Waiting {delay:.1f}s before next chunk...")
                time.sleep(delay)
        except Exception as e:
            return {"error": str(e)}
    return full_result
"""
"""
def analyze_code(code_content, prompt_template):
    chunks = split_code_to_chunks(code_content, model=MODEL, max_tokens_per_chunk=7168)
    full_result = {}
    enc = tiktoken.encoding_for_model(MODEL)

    for i, chunk in enumerate(chunks):
        code_with_lines = add_line_numbers(chunk)
        prompt = f"{prompt_template}\nAnalyze the following code. Each line is prefixed with a line number:\n\n{code_with_lines}"

        try:
            print(f"📤 Sending chunk {i+1}/{len(chunks)} | size ≈ {len(enc.encode(chunk))} tokens")

            response = client.chat.completions.create(
                model=MODEL,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.2,
                top_p=0.1,
                max_tokens=8192
            )

            chunk_result = extract_json_from_response(response.choices[0].message.content)
            full_result = merge_results(full_result, chunk_result)

            if i < len(chunks) - 1:
                delay = random.uniform(30, 60)
                print(f"⏳ Waiting {delay:.1f}s before next chunk...")
                time.sleep(delay)

        except Exception as e:
            return {"error": f"Error in chunk {i+1}: {str(e)}"}

    return full_result
"""




# def analyze_code(code_content, prompt_template, max_retries=3):
#     chunks = split_code_to_chunks(code_content)
#     full_result = {}

#     for i, chunk in enumerate(chunks):
#         code_with_lines = add_line_numbers(chunk)

#         token_count = len(tiktoken.encoding_for_model("gpt-4o").encode(chunk))
#         print(f"Chunk {i+1} size in tokens: {token_count}")

#         prompt = (
#             f"{prompt_template}\n"
#             "Analyze the following code. Each line is prefixed with a line number.\n"
#             "IMPORTANT: Return ONLY a valid JSON object without any additional text or explanation.\n\n"
#             f"{code_with_lines}"
#         )

#         retry_count = 0
#         while retry_count <= max_retries:
#             try:
#                 print(f"📤 Sending chunk {i+1}/{len(chunks)} | approx tokens: {len(tiktoken.encoding_for_model(MODEL).encode(chunk))}")
#                 response = client.chat.completions.create(
#                     model=MODEL,
#                     messages=[{"role": "user", "content": prompt}],
#                     temperature=0.2,
#                     top_p=0.1,
#                     max_tokens=8192
#                 )
#                 chunk_result = extract_json_from_response(response.choices[0].message.content)
#                 print(f"🔍 Parsed JSON result from chunk {i+1}:\n{json.dumps(chunk_result, indent=2)}")  # debug print
#                 full_result = merge_results(full_result, chunk_result)

#                 if i < len(chunks) - 1:
#                     print("⏳ Waiting 15 seconds before next chunk...")
#                     time.sleep(3)

#                 break  # success, exit retry loop

#             except Exception as e:
#                 err_msg = str(e)
#                 if "429" in err_msg or "rate_limit" in err_msg.lower():
#                     retry_count += 1
#                     wait_time = 3 * retry_count
#                     print(f"⚠️ Rate limit hit. Retry {retry_count}/{max_retries} after {wait_time}s wait. {err_msg}")
#                     time.sleep(wait_time)
#                 else:
#                     print(f"❌ Error in chunk {i+1}: {err_msg}")
#                     return {"error": err_msg}

#         if retry_count > max_retries:
#             print(f"❌ Failed chunk {i+1} after {max_retries} retries due to rate limits.")
#             return {"error": f"Rate limit exceeded after {max_retries} retries"}

#     return full_result



"""
def analyze_code(code_content, prompt_template, github_username="", repo_name="", branch_name="main", repo_file_path=""):
    chunks = split_code_to_chunks(code_content)
    encoder = tiktoken.encoding_for_model("gpt-4o")

    for i, chunk in enumerate(chunks):
        code_with_lines = add_line_numbers(chunk)
        token_count = len(encoder.encode(chunk))
        print(f"Chunk {i+1} size in tokens: {token_count}")

        prompt = (
            f"{prompt_template}\n"
            "Analyze the following code. Each line is prefixed with a line number.\n"
            "IMPORTANT: Return ONLY a valid JSON object without any additional text or explanation.\n\n"
            f"{code_with_lines}"
        )

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

                chunk_result = extract_json_from_response(response.choices[0].message.content)
                print(f"🔍 Parsed JSON result from chunk {i+1}:\n{json.dumps(chunk_result, indent=2)}")

                # Attach file_path and save directly
                chunk_result["file_path"] = repo_file_path
                categorize_and_save(
                    chunk_result,
                    github_username=github_username,
                    repo_name=repo_name,
                    branch_name=branch_name
                )

                time.sleep(3)
                break  # exit retry loop

            except Exception as e:
                if "429" in str(e) or "rate limit" in str(e).lower():
                    wait = 3 * (retry_count + 1)
                    print(f"⚠️ Rate limit. Retrying after {wait}s")
                    time.sleep(wait)
                else:
                    print(f"❌ Error in chunk {i+1}: {e}")
                    return {"error": str(e)}

    return {"status": "all_chunks_saved"}
"""



def analyze_code(code_content, prompt_template, github_username="", repo_name="", branch_name="main", repo_file_path=""):
    chunks = split_code_to_chunks(code_content)
    encoder = tiktoken.encoding_for_model("gpt-4o")

    for i, chunk in enumerate(chunks):
        code_with_lines = add_line_numbers(chunk)
        token_count = len(encoder.encode(chunk))
        print(f"Chunk {i+1} size in tokens: {token_count}")

        prompt = f"{prompt_template}\nAnalyze the following code. Each line is prefixed with a line number for reference:\n\n{code_with_lines}"

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

                # if not isinstance(chunk_result, dict):
                #     print(f"⚠️ Skipping chunk {i+1}: Invalid JSON structure")
                #     continue

                #print(f"🔍 Parsed JSON result from chunk {i+1}:\n{json.dumps(chunk_result, indent=2)}")

                # Add metadata before saving
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

"""
def categorize_and_save(data, github_username, repo_name, branch_name="main", email="", platform="GitHub"):
    result = data.get("result", data)
   
    print(result)
    print("sundar was here")
    repo_file_path = data.get("file_path", "")

    db = get_db_connection()
    cursor = db.cursor()

    try:
        for category in CATEGORIES:
            section = result.get(category)
            if not section:
                continue

            table_name = CATEGORY_TABLE_MAP[category]
            issues = []

            def normalize_issue(issue, category):
                if not isinstance(issue, dict):
                    return None

            def b64(s):
                if isinstance(s, str):
                    return base64.b64encode(s.encode("utf-8")).decode("utf-8")
                return s
            

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
                    "severity": issue.get("severity", "Medium"),
                    "short_description": issue.get("description") or issue.get("short_description", ""),
                    "suggested_fix": issue.get("suggested_fix", "Review the code and apply necessary validation/sanitization."),
                    "created_at": datetime.now(),
                    "bad_practice": issue.get("bad_practice", "") if category in ["smelly_code", "malicious_code"] else None,
                    "good_practice": issue.get("good_practice", "") if category in ["smelly_code", "malicious_code"] else None,
                    "issueId": issue.get("issue_id") or issue.get("id") or "",
                    "branch": branch_name
                }
                # if category == "owasp_security":
                #     base_issue["bad_practice"] = issue.get("vulnerable_code", "")
                #     base_issue["good_practice"] = issue.get("patched_code", "")
                # return base_issue

                if category in ["smelly_code", "malicious_code"]:
                    base_issue["bad_practice"] = b64(issue.get("bad_practice", ""))
                    base_issue["good_practice"] = b64(issue.get("good_practice", ""))
             
                if category == "owasp_security":
                     base_issue["bad_practice"] = b64(issue.get("vulnerable_code", ""))
                     base_issue["good_practice"] = b64(issue.get("patched_code", ""))

                print("sundar was here1\n")

                return base_issue


            if isinstance(section, dict):
                for _, issue_list in section.items():
                    for i in issue_list:
                        norm = normalize_issue(i, category)
                        if norm:
                            issues.append(norm)
            elif isinstance(section, list):
                for i in section:
                    norm = normalize_issue(i, category)
                    if norm:
                        issues.append(norm)

            if not issues:
                continue

            print("sundar was here2\n")

            keys = issues[0].keys()
            fields = ", ".join(keys)
            placeholders = ", ".join(["%s"] * len(keys))
            insert_query = f"INSERT INTO {table_name} ({fields}) VALUES ({placeholders})"

            print("sundar was here3\n")

            for issue in issues:
                cursor.execute(insert_query, list(issue.values()))
            print(f"✅ Inserted {len(issues)} into {table_name}")
        db.commit()
        print("sundar was here4\n")

    except Exception as e:
        db.rollback()
        print(f"❌ Error inserting: {e}")
    finally:
        cursor.close()
        db.close()
"""


def categorize_and_save(data, github_username, repo_name, branch_name="main", email="", platform="GitHub"):

    #result = data["result"]
   
    result = data.get("result", data)
    # print(github_username)
    # print(repo_name)
    # print(result)

    #repo_file_path = data["file_path"]  # e.g., "src/app.js"
    repo_file_path = data.get("file_path", "")
    github_style_path = f"{github_username}/{repo_name}/blob/{branch_name}/{repo_file_path}"

    def normalize_issue(issue, category):
        if not isinstance(issue, dict):
            return None

        def b64(s):
            if isinstance(s, str):
                return base64.b64encode(s.encode("utf-8")).decode("utf-8")
            return s


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
            "severity": issue.get("severity", "Medium"),
            "short_description": issue.get("description") or issue.get("short_description", ""),
            "suggested_fix": issue.get("suggested_fix", "Review the code and apply necessary validation/sanitization."),
            "created_at": datetime.now(),
            "bad_practice": (issue.get("bad_practice", "")) if category in ["smelly_code", "malicious_code"] else None,
            "good_practice": issue.get("good_practice", "") if category in ["smelly_code", "malicious_code"] else None,
            "issueId": issue.get("issue_id") or issue.get("id") or "",  # if available
            "branch": branch_name
        }
        if category == "owasp_security":
            base_issue["bad_practice"] = (issue.get("vulnerable_code", ""))
            base_issue["good_practice"] = issue.get("patched_code", "")

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

def get_repo_files(username, repo, branch, token):
    url = f"https://api.github.com/repos/{username}/{repo}/git/trees/{branch}?recursive=1"
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(url, headers=headers, timeout=20)
    response.raise_for_status()
    tree = response.json().get("tree", [])
    return [item for item in tree if item["type"] == "blob" and Path(item["path"]).suffix in ALLOWED_EXTENSIONS]

def download_file(username, repo, path, token, branch="main"):
    url = f"https://api.github.com/repos/{username}/{repo}/contents/{path}?ref={branch}"
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(url, headers=headers, timeout=20)
    response.raise_for_status()
    content = base64.b64decode(response.json()["content"]).decode("utf-8", errors="ignore")
    return content

def get_access_token(username):
    url = f"{SITE_URL}/getToken"
    response = requests.post(url, json={"username": username}, headers={"Content-Type": "application/json"}, timeout=10)
    response.raise_for_status()
    return response.json()['data']['client_access_token']

def process_file(file, username, repo, branch, token, prompt_template, max_retries=2):
    path = file["path"]
    for attempt in range(1, max_retries + 1):
        try:
            print(f"📥 Downloading: {path} (Attempt {attempt})")
            content = download_file(username, repo, path, token, branch)

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

def main():
    if len(sys.argv) < 3:
        print("Usage: python scanner.py <username> <repo> [branch]")
        sys.exit(1)

    username, repo = sys.argv[1], sys.argv[2]
    branch = sys.argv[3] if len(sys.argv) > 3 else None
    print(f"🔍 Analyzing {username}/{repo}...")

    try:
        token = get_access_token(username)
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
                executor.submit(process_file, file, username, repo, valid_branch, token, prompt_template)
                for file in files
            ]
            for future in as_completed(futures):
                print(future.result())

        print("✅ All files processed.")
    except Exception as e:
        print(f"❌ Fatal error: {e}")

if __name__ == "__main__":
    main()
