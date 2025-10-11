class RiskAnalyzer:
    def __init__(self):
        self.severity_weights = {
            "Critical": 1.0,
            "High": 0.7,
            "Medium": 0.4,
            "Low": 0.2
        }
        
        self.owasp_weights = {
            # OWASP 2021 Top 10 weights
            "A01:2021-Broken Access Control": 0.95,
            "A02:2021-Cryptographic Failures": 0.85,
            "A03:2021-Injection": 0.95,
            "A04:2021-Insecure Design": 0.75,
            "A05:2021-Security Misconfiguration": 0.65,
            "A06:2021-Vulnerable and Outdated Components": 0.80,
            "A07:2021-Identification and Authentication Failures": 0.85,
            "A08:2021-Software and Data Integrity Failures": 0.80,
            "A09:2021-Security Logging and Monitoring Failures": 0.50,
            "A10:2021-Server-Side Request Forgery": 0.75,
            
            # OWASP 2017 for backward compatibility
            "A1:2017-Injection": 0.95,
            "A2:2017-Broken Authentication": 0.85,
            "A3:2017-Sensitive Data Exposure": 0.85,
            "A4:2017-XML External Entities (XXE)": 0.80,
            "A5:2017-Broken Access Control": 0.95,
            "A6:2017-Security Misconfiguration": 0.65,
            "A7:2017-Cross-Site Scripting (XSS)": 0.75,
            "A8:2017-Insecure Deserialization": 0.80,
            "A9:2017-Using Components with Known Vulnerabilities": 0.80,
            "A10:2017-Insufficient Logging & Monitoring": 0.50
        }
        
        self.vulnerability_weights = {
            # Critical vulnerabilities
            "Remote Code Execution": 0.95,
            "SQL Injection": 0.95,
            "Command Injection": 0.95,
            "Arbitrary File Upload": 0.90,
            "Insecure Deserialization": 0.90,
            "Server-Side Request Forgery": 0.85,
            "XXE Injection": 0.85,
            
            # High impact vulnerabilities
            "Broken Authentication": 0.85,
            "Broken Access Control": 0.85,
            "IDOR": 0.85,
            "Privilege Escalation": 0.85,
            "Sensitive Data Exposure": 0.80,
            "Cryptographic Failures": 0.80,
            
            # Medium impact vulnerabilities
            "XSS": 0.75,
            "CSRF": 0.70,
            "Security Misconfiguration": 0.65,
            "Vulnerable Components": 0.70,
            
            # Code quality issues
            "Hardcoded Secrets": 0.60,
            "Insecure Storage": 0.55,
            "Missing Docstring": 0.10,
            "Dead Code": 0.15,
            "Smelly Code": 0.20,
            "Malicious Code": 0.95
        }
        
        self.cwe_weights = {
            "CWE-89": 0.95,   # SQL Injection
            "CWE-78": 0.95,   # OS Command Injection
            "CWE-79": 0.75,   # XSS
            "CWE-352": 0.70,  # CSRF
            "CWE-22": 0.80,   # Path Traversal
            "CWE-434": 0.90,  # Unrestricted Upload
            "CWE-502": 0.90,  # Deserialization
            "CWE-918": 0.85,  # SSRF
            "CWE-306": 0.85,  # Missing Authentication
            "CWE-862": 0.85,  # Missing Authorization
            "CWE-798": 0.60,  # Hardcoded Credentials
            "CWE-327": 0.80,  # Broken Crypto
            "CWE-200": 0.70,  # Information Exposure
            "CWE-400": 0.65,  # Uncontrolled Resource Consumption
            "CWE-611": 0.85,  # XXE
        }

    def calculate_risk_score(self, issue):
        """Calculate risk score (0-100) for an individual issue"""
        base_score = 0
        
        # 1. Severity weight (40% of score)
        severity = issue.get("severity", "Medium")
        severity_weight = self.severity_weights.get(severity, 0.4)
        base_score += severity_weight * 40
        
        # 2. OWASP category weight (30% of score)
        owasp_2021 = issue.get("owasp_2021")
        owasp_2017 = issue.get("owasp_2017")
        
        owasp_weight = 0.3
        if owasp_2021:
            owasp_weight = self.owasp_weights.get(owasp_2021, 0.5)
        elif owasp_2017:
            owasp_weight = self.owasp_weights.get(owasp_2017, 0.5)
        base_score += owasp_weight * 30
        
        # 3. Vulnerability type weight (20% of score)
        vuln_type = issue.get("vulnerability_type", "")
        vuln_weight = self.vulnerability_weights.get(vuln_type, 0.3)
        base_score += vuln_weight * 20
        
        # 4. CWE weight (10% of score)
        cwe = issue.get("cwe", "")
        cwe_id = cwe.split(":")[0] if ":" in cwe else ""
        cwe_weight = self.cwe_weights.get(cwe_id, 0.3)
        base_score += cwe_weight * 10
        
        # Cap the score at 100
        risk_score = min(100, int(base_score))
        
        return risk_score
    
    def get_risk_level(self, score):
        """Convert numerical score to risk level"""
        if score >= 80:
            return "Critical"
        elif score >= 60:
            return "High"
        elif score >= 40:
            return "Medium"
        elif score >= 20:
            return "Low"
        else:
            return "Info"
    
    def analyze_issue_risk(self, issue):
        """Complete risk analysis for an issue"""
        risk_score = self.calculate_risk_score(issue)
        risk_level = self.get_risk_level(risk_score)
        
        return {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "severity": issue.get("severity", "Medium"),
            "vulnerability_type": issue.get("vulnerability_type", ""),
            "owasp_category": issue.get("owasp_2021") or issue.get("owasp_2017", ""),
            "cwe": issue.get("cwe", "")
        }