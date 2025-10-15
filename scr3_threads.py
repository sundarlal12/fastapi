import sys
import os
import requests
import base64
import mysql.connector  
from dotenv import load_dotenv
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
from datetime import datetime
import yaml
import re
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
    "dead_code",
    "docstring",
    "malicious_code",
    "owasp_security",
    "secrets",
    "smelly_code"
]

CATEGORY_TABLE_MAP = {
    "dead_code": "dead_code_info",
    "docstring": "docstring_info",
    "malicious_code": "malicious_code_info",
    "owasp_security": "owasp_security_info",
    "secrets": "secrets_info",
    "smelly_code": "smelly_code_info"
}


ALLOWED_EXTENSIONS = {'.py', '.js', '.java', '.cpp', '.php', '.html', '.ts', '.rb', '.go', '.c', '.rs'}


def get_db_connection():
    return mysql.connector.connect(**DB_CONFIG)


def load_prompt_template(path="review_prompt.yml"):
    with open(path, "r") as file:
        yml = yaml.safe_load(file)
        return yml["review_template"]

def extract_json_from_response(text):
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r'{[\s\S]+}', text)
        if match:
            try:
                return json.loads(match.group())
            except json.JSONDecodeError as e:
                print(f"⚠️ JSON decoding failed after regex extract: {e}")
                return {"error": "Malformed JSON after regex extract"}
        return {"error": "No valid JSON found in output"}

def add_line_numbers(code):
    return "\n".join(f"{i+1}: {line}" for i, line in enumerate(code.splitlines()))

def analyze_code(code_content, prompt_template):
    code_with_lines = add_line_numbers(code_content)
    prompt = f"{prompt_template}\nAnalyze the following code. Each line is prefixed with a line number for reference:\n\n{code_with_lines}"
    try:
        response = client.chat.completions.create(
            model=MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
            top_p=0.1,
            max_tokens=8192
        )
        return extract_json_from_response(response.choices[0].message.content)
    except Exception as e:
        return {"error": str(e)}


def categorize_and_save(data, github_username, repo_name, branch_name="main", email="", platform="GitHub"):

    #result = data["result"]
   
    result = data.get("result", data)
    print(result)

    #repo_file_path = data["file_path"]  # e.g., "src/app.js"
    repo_file_path = data.get("file_path", "")
    github_style_path = f"{github_username}/{repo_name}/blob/{branch_name}/{repo_file_path}"

    def normalize_issue(issue, category):
        if not isinstance(issue, dict):
            return None
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
            "issueId": issue.get("issue_id") or issue.get("id") or "",  # if available
            "branch": branch_name
        }
        if category == "owasp_security":
            base_issue["bad_practice"] = issue.get("vulnerable_code", "")
            base_issue["good_practice"] = issue.get("patched_code", "")


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
        url = f"https://api.github.com/repos/{username}/{repo}/branches/{branch}"
        headers = {"Authorization": f"Bearer {token}"}
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return branch
    raise Exception("❌ Neither main nor master branch found.")

def get_repo_files(username, repo, branch, token):
    url = f"https://api.github.com/repos/{username}/{repo}/git/trees/{branch}?recursive=1"
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    tree = response.json().get("tree", [])
    return [item for item in tree if item["type"] == "blob" and Path(item["path"]).suffix in ALLOWED_EXTENSIONS]

# def download_file(username, repo, path, token):
#     url = f"https://api.github.com/repos/{username}/{repo}/contents/{path}"
#     headers = {"Authorization": f"Bearer {token}"}
#     response = requests.get(url, headers=headers)
#     response.raise_for_status()
#     content = base64.b64decode(response.json()["content"]).decode("utf-8", errors="ignore")
#     return content

def download_file(username, repo, path, token, branch="main"):
    url = f"https://api.github.com/repos/{username}/{repo}/contents/{path}?ref={branch}"
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    content = base64.b64decode(response.json()["content"]).decode("utf-8", errors="ignore")
    return content


def get_access_token(username):
    url = f"{SITE_URL}/getToken"
    response = requests.post(url, json={"username": username}, headers={"Content-Type": "application/json"})
    response.raise_for_status()
    return response.json()['data']['client_access_token']


"""
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
        #print(files)
        prompt_template = load_prompt_template()

        for file in files:
            print(f"📁 Processing: {file['path']}")
            code = download_file(username, repo, file["path"], token)
            result = analyze_code(code, prompt_template)
            print(result)
            
            # Pass username, repo, branch here
            categorize_and_save(
                {"file_path": file["path"], "result": result},
                github_username=username,
                repo_name=repo,
                branch_name=valid_branch
            )
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()
"""
"""
def process_file(file, username, repo, token, prompt_template, valid_branch):
    try:
        print(f"📥 Downloading: {file['path']}")
        content = download_file(username, repo, file['path'], token)

        print(f"🤖 Analyzing: {file['path']}")
        result = analyze_code(content, prompt_template)

        print(f"💾 Saving results for: {file['path']}")
        result["file_path"] = file["path"]
        categorize_and_save(result, username, repo, branch_name=valid_branch)

        return f"✅ Processed: {file['path']}"
    except Exception as e:
        return f"❌ Error processing {file['path']}: {str(e)}"
"""
"""
def process_file(file, username, repo, branch, token, prompt_template):
    try:
        time.sleep(random.uniform(1.2, 2.0))

        path = file["path"]
        print(f"📥 Downloading: {path}")
        content = download_file(username, repo, path, token)
        print(f"🤖 Analyzing: {path}")
        analysis = analyze_code(content, prompt_template)
        print(analysis)

        if not isinstance(analysis, dict):
            print(f"❌ Skipping {path}: Analysis did not return a dict")
            return

        # if "result" not in analysis:
        #     print(f"❌ Skipping {path}: 'result' key missing. Full response: {analysis}")
        #     return

        analysis["file_path"] = path
        categorize_and_save(
            analysis,
            github_username=username,
            repo_name=repo,
            branch_name=branch
        )
        print(f"💾 Saved results for: {path}")

    except Exception as e:
        print(f"❌ Error processing {file['path']}: {e}")
"""
def process_file(file, username, repo, branch, token, prompt_template):
    try:
        time.sleep(random.uniform(1.2, 2.0))  # To respect rate limits and avoid throttling

        path = file["path"]
        print(f"📥 Downloading: {path}")
        content = download_file(username, repo, path, token, branch)
        
        print(f"🤖 Analyzing: {path}")
        analysis = analyze_code(content, prompt_template)

        if not isinstance(analysis, dict):
            print(f"❌ Skipping {path}: Analysis did not return a dict")
            return

        analysis["file_path"] = path

        print(f"💾 Saving analysis results for: {path}")
        categorize_and_save(
            analysis,
            github_username=username,
            repo_name=repo,
            branch_name=branch
        )

        return f"✅ Processed: {path}"
    except Exception as e:
        return f"❌ Error processing {file['path']}: {str(e)}"



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
            print("⚠️ No valid code files found in the repository.")
            return

        prompt_template = load_prompt_template()

        results = []
        max_threads = min(10, len(files))  # Limit concurrency

        print(f"🚀 Starting threaded processing with {max_threads} threads...")

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [
                executor.submit(process_file, file, username, repo, valid_branch, token, prompt_template)
                for file in files
            ]

            for future in as_completed(futures):
                result = future.result()
                print(result)

        print("✅ All files processed.")

    except Exception as e:
        print(f"❌ Fatal error: {str(e)}")


if __name__ == "__main__":
    main()
