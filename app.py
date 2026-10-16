from flask import Flask, render_template, request, jsonify, Response
import sqlite3
import ast
import re
import os
from groq import Groq

app = Flask(__name__)

# CRITICAL SECURITY FIX: Never hardcode API keys. 
# We fetch it from the environment variable now.
api_key = os.environ.get("GROQ_API_KEY")
client = Groq(api_key=api_key)

def init_db():
    conn = sqlite3.connect('code_clerk.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS review_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code_snippet TEXT,
            security_score INTEGER,
            issues_found TEXT,
            language TEXT
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# Advanced AST Security Scanner for Python
class SecurityVisitor(ast.NodeVisitor):
    def __init__(self):
        self.issues = []

    def visit_Call(self, node):
        if isinstance(node.func, ast.Name) and node.func.id in ['eval', 'exec']:
            self.issues.append("Security Critical: Use of dangerous function 'eval()' or 'exec()' detected.")
        self.generic_visit(node)

    def visit_FunctionDef(self, node):
        if not ast.get_docstring(node):
            self.issues.append(f"Code Quality Warning: Function '{node.name}' lacks a docstring.")
        self.generic_visit(node)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/review', methods=['POST'])
def review_code():
    code_text = request.form.get('code_text', '')
    language = request.form.get('language', 'python')
    action_type = request.form.get('action_type', 'audit')
    
    issues = []
    score = 100
    
    if action_type == 'audit':
        # 1. Regex & AST Logic only for Auditing existing code
        if re.search(r'(password|api_key|secret|token|auth)\s*=\s*[\'"][^\'"]+[\'"]', code_text, re.IGNORECASE):
            issues.append("Security Critical: Hardcoded credentials or secrets detected via Regex!")
        
        if language == 'python':
            try:
                tree = ast.parse(code_text)
                visitor = SecurityVisitor()
                visitor.visit(tree)
                issues.extend(visitor.issues)
            except SyntaxError as se:
                issues.append(f"Syntax Error: Invalid Python syntax at line {se.lineno}")

        score = 100 - (len(issues) * 20)
        if score < 30:
            score = 30
            
        system_prompt = "You are an intelligent DevSecOps AI Assistant. Perform a vulnerability and performance audit of the provided code, explaining the risks and providing a secure, refactored version."
        user_prompt = f"Language: {language}\n\nCode snippet to audit:\n\n{code_text}"
        message_text = "Hybrid AST + AI Audit completed successfully."
        
    else:
        # 2. Logic for Secure Code Generation
        issues.append("N/A - Secure Code Generation Mode")
        system_prompt = "You are an intelligent DevSecOps AI Assistant. The user will give you a requirement. You must generate secure, vulnerability-free code to fulfill this requirement. Include comments explaining the security best practices applied."
        user_prompt = f"Language: {language}\n\nRequirement for Secure Code Generation:\n\n{code_text}"
        message_text = "Secure Code Generated Successfully."

    ai_feedback = "AI Review unavailable."
    try:
        completion = client.chat.completions.create(
            model="openai/gpt-oss-120b",
            messages=[
                {
                    "role": "system",
                    "content": system_prompt
                },
                {
                    "role": "user",
                    "content": user_prompt
                }
            ],
            temperature=0.2,
            max_tokens=1000
        )
        ai_feedback = completion.choices[0].message.content
    except Exception as e:
        ai_feedback = f"AI Cloud Error: {str(e)}"

    # Database Insertion
    conn = sqlite3.connect('code_clerk.db')
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO review_history (code_snippet, security_score, issues_found, language)
        VALUES (?, ?, ?, ?)
    ''', (code_text, score, str(issues), language))
    conn.commit()
    
    last_id = cursor.lastrowid
    conn.close()

    result_data = {
        "review_id": last_id,
        "security_score": score,
        "issues_found": issues if action_type == 'audit' else [],
        "ai_feedback": ai_feedback,
        "language": language,
        "mode": action_type,
        "message": message_text
    }

    return render_template('index.html', result=result_data)

@app.route('/history')
def view_history():
    conn = sqlite3.connect('code_clerk.db')
    cursor = conn.cursor()
    cursor.execute('SELECT id, code_snippet, security_score, issues_found, language FROM review_history ORDER BY id DESC')
    rows = cursor.fetchall()
    conn.close()
    return render_template('history.html', history=rows)

@app.route('/download/<int:review_id>')
def download_report(review_id):
    conn = sqlite3.connect('code_clerk.db')
    cursor = conn.cursor()
    cursor.execute('SELECT code_snippet, security_score, issues_found, language FROM review_history WHERE id = ?', (review_id,))
    row = cursor.fetchone()
    conn.close()
    
    if not row:
        return "Report not found", 404
        
    report_content = f"""==================================================
        CODE-CLERK: DEVSECOPS SECURITY AUDIT REPORT
==================================================
Review ID:     {review_id}
Language:      {row[3].upper()}
Security Score: {row[1]} / 100
--------------------------------------------------
DETECTED VULNERABILITIES & WARNINGS (LOCAL AST):
{row[2]}
--------------------------------------------------
SOURCE TEXT/CODE SUBMITTED:
{row[0]}
==================================================
"""
    return Response(
        report_content,
        mimetype="text/plain",
        headers={"Content-disposition": f"attachment; filename=security_audit_report_{review_id}.txt"}
    )

if __name__ == '__main__':
    app.run(debug=True, port=5000)